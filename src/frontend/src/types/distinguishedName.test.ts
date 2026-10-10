import { describe, it, expect } from 'vitest';
import { extractCN, certificateDisplayName } from './index';

/**
 * Tests for the common name reader in src/types/index.ts.
 *
 * That reader is a hand written mirror of DistinguishedNameParser in
 * src/Certus.Core/Adcs/DistinguishedNameParser.cs, and the two have to give the
 * same answer for the same subject: the C# side names the row in the activity
 * feed and keys the supersession lineage, and this side names it in the
 * inventory, the detail heading, and the revoke dialog's typed confirmation. A
 * fourth answer is exactly the defect issue #231 closed, and until issue #296
 * this file had no tests at all while the C# side had forty.
 *
 * The corpus below mirrors AwkwardValues in
 * tests/Certus.Core.Tests/Adcs/DistinguishedNameParserTests.cs. It cannot be
 * shared literally across the two languages, so the two lists move together by
 * hand; add a value in one place and add it in the other.
 *
 * What is shared is stronger than the list itself. The C# theory builds each
 * value into a real X.500 name and compares the reader against
 * X500DistinguishedName.EnumerateRelativeDistinguishedNames, so the encoded
 * value is the oracle there. Node has no Windows name encoder, so the renderings
 * below were measured on net10.0-windows from the same builder rather than
 * guessed, and the expectation is the value that went in. That keeps this suite
 * anchored to what Windows actually writes instead of to what this reader
 * happens to do.
 */

/** value: what the certificate carries. rendered: what Windows writes for it. */
interface Case {
  value: string;
  /** The value as the common name, with an organisation after it. */
  asCommonName: string;
  /** The value as an organisation name, with the common name after it. */
  beforeCommonName: string;
}

const CORPUS: Case[] = [
  {
    value: 'plain.example.com',
    asCommonName: 'CN=plain.example.com, O=Real Org',
    beforeCommonName: 'O=plain.example.com, CN=leaf.example.com',
  },
  {
    value: 'evil, O=Trusted Corp',
    asCommonName: 'CN="evil, O=Trusted Corp", O=Real Org',
    beforeCommonName: 'O="evil, O=Trusted Corp", CN=leaf.example.com',
  },
  {
    value: 'Acme, CN=trusted.example.com, Ltd',
    asCommonName: 'CN="Acme, CN=trusted.example.com, Ltd", O=Real Org',
    beforeCommonName: 'O="Acme, CN=trusted.example.com, Ltd", CN=leaf.example.com',
  },
  {
    value: 'has+plus',
    asCommonName: 'CN="has+plus", O=Real Org',
    beforeCommonName: 'O="has+plus", CN=leaf.example.com',
  },
  {
    value: 'has"quote',
    asCommonName: 'CN="has""quote", O=Real Org',
    beforeCommonName: 'O="has""quote", CN=leaf.example.com',
  },
  {
    value: 'has\\backslash',
    asCommonName: 'CN=has\\backslash, O=Real Org',
    beforeCommonName: 'O=has\\backslash, CN=leaf.example.com',
  },
  {
    value: 'CORP\\ab-server',
    asCommonName: 'CN=CORP\\ab-server, O=Real Org',
    beforeCommonName: 'O=CORP\\ab-server, CN=leaf.example.com',
  },
  // The three that end in a backslash are issue #296. A backslash in the middle
  // of a value is followed by a character of the name; one at the end is
  // followed by the separator that starts the next component, which is where a
  // reader that treats it as an escape steps over the boundary.
  {
    value: 'CORP\\',
    asCommonName: 'CN=CORP\\, O=Real Org',
    beforeCommonName: 'O=CORP\\, CN=leaf.example.com',
  },
  {
    value: '\\',
    asCommonName: 'CN=\\, O=Real Org',
    beforeCommonName: 'O=\\, CN=leaf.example.com',
  },
  {
    value: 'CORP\\svc\\',
    asCommonName: 'CN=CORP\\svc\\, O=Real Org',
    beforeCommonName: 'O=CORP\\svc\\, CN=leaf.example.com',
  },
  // These three end in a backslash and also carry a character Windows quotes
  // for, which puts the backslash immediately in front of the closing quote
  // rather than in front of the separator. That is the one place the quoting
  // mechanism and a literal backslash meet. The last one has no quoting at all
  // and ends in two backslashes, which used to read back one short.
  {
    value: 'a,b\\',
    asCommonName: 'CN="a,b\\", O=Real Org',
    beforeCommonName: 'O="a,b\\", CN=leaf.example.com',
  },
  {
    value: 'a"b\\',
    asCommonName: 'CN="a""b\\", O=Real Org',
    beforeCommonName: 'O="a""b\\", CN=leaf.example.com',
  },
  {
    value: 'a\\\\',
    asCommonName: 'CN=a\\\\, O=Real Org',
    beforeCommonName: 'O=a\\\\, CN=leaf.example.com',
  },
  {
    value: '\\74\\72\\75\\73\\74\\65\\64.example.com',
    asCommonName: 'CN=\\74\\72\\75\\73\\74\\65\\64.example.com, O=Real Org',
    beforeCommonName: 'O=\\74\\72\\75\\73\\74\\65\\64.example.com, CN=leaf.example.com',
  },
  {
    value: '  leading and trailing  ',
    asCommonName: 'CN="  leading and trailing  ", O=Real Org',
    beforeCommonName: 'O="  leading and trailing  ", CN=leaf.example.com',
  },
  {
    value: 'semi;colon',
    asCommonName: 'CN="semi;colon", O=Real Org',
    beforeCommonName: 'O="semi;colon", CN=leaf.example.com',
  },
  {
    value: 'equals=sign',
    asCommonName: 'CN="equals=sign", O=Real Org',
    beforeCommonName: 'O="equals=sign", CN=leaf.example.com',
  },
  {
    value: 'unicode umlaut ü',
    asCommonName: 'CN=unicode umlaut ü, O=Real Org',
    beforeCommonName: 'O=unicode umlaut ü, CN=leaf.example.com',
  },
  {
    value: 'CN=looks like a type',
    asCommonName: 'CN="CN=looks like a type", O=Real Org',
    beforeCommonName: 'O="CN=looks like a type", CN=leaf.example.com',
  },
];

describe('extractCN across the awkward value corpus', () => {
  it.each(CORPUS)('reads $value back out of its own rendering', ({ value, asCommonName }) => {
    expect(extractCN(asCommonName)).toBe(value);
  });

  it.each(CORPUS)(
    'is not derailed by $value sitting ahead of the common name',
    ({ beforeCommonName }) => {
      // The position a planted "CN=" would occupy. ADCS encodes general to
      // specific, so every requester authored part comes ahead of the common
      // name on an ordinary certificate.
      expect(extractCN(beforeCommonName)).toBe('leaf.example.com');
    },
  );
});

describe('extractCN grammar', () => {
  it('returns the whole subject when there is no common name', () => {
    // The fallback is reached often rather than rarely: a SAN only certificate
    // is stored with a bare name and no "CN=" at all.
    expect(extractCN('host.example.com')).toBe('host.example.com');
    expect(extractCN('OU=IT, O=Example')).toBe('OU=IT, O=Example');
    expect(extractCN('')).toBe('');
    expect(extractCN('   ')).toBe('   ');
  });

  it('reads ordinary shapes whatever the case, spacing or separator', () => {
    expect(extractCN('CN=leaf.example.com')).toBe('leaf.example.com');
    expect(extractCN('C=US, O=Example, CN=leaf.example.com')).toBe('leaf.example.com');
    expect(extractCN('cn=leaf.example.com')).toBe('leaf.example.com');
    expect(extractCN('Cn = leaf.example.com , OU=IT')).toBe('leaf.example.com');
    expect(extractCN('C=US; O=Example; CN=leaf.example.com')).toBe('leaf.example.com');
  });

  it('treats a quoted comma as part of the name, not a separator', () => {
    // The defect issue #231 closed. Reading to the first comma returned the
    // fragment '"evil', which is neither the name in the certificate nor a name
    // any admin could act on.
    expect(extractCN('CN="evil, O=Trusted Corp", O=Real Org')).toBe('evil, O=Trusted Corp');
  });

  it('treats a doubled quote inside a quoted value as one literal quote', () => {
    // How CertNameToStr writes a quote that was already in the name. The inner
    // pair must not read as closing and reopening the value.
    expect(extractCN('CN="say ""hi"", friend", O=Example')).toBe('say "hi", friend');
  });

  it('never decodes a hex escape', () => {
    // Issue #238. CertNameToStr has no escaping form, so the only way "\74"
    // arrives is because a requester put those characters in the name and
    // Windows stored them verbatim. Read as hex the seven of them spell
    // "trusted", which is a name the certificate does not carry.
    const planted = '\\74\\72\\75\\73\\74\\65\\64.example.com';

    expect(extractCN(`CN=${planted}, O=Real Org`)).toBe(planted);
    expect(extractCN(`CN=${planted}, O=Real Org`)).not.toBe('trusted.example.com');
  });

  it('keeps a literal backslash in the middle of a value', () => {
    // Issue #238's correctness half. "DOMAIN\user" shapes are ordinary in a
    // distinguished name, and resolving the character after the backslash
    // dropped it: "CORP\svc" read back as "CORPsvc".
    expect(extractCN('CN=CORP\\admin, O=Example')).toBe('CORP\\admin');
    expect(extractCN('CN=CORP\\ab-server, O=Example')).toBe('CORP\\ab-server');
    expect(extractCN('CN=has\\backslash, O=Example')).toBe('has\\backslash');
  });

  it('does not let a trailing backslash swallow the next component', () => {
    // Issue #296. Windows renders a value ending in a backslash bare, so the
    // backslash lands immediately in front of the ", " that starts the next
    // component. Reading it as an escape stepped over that separator and
    // decoded the rest of the subject into the name.
    expect(extractCN('CN=CORP\\, O=Example')).toBe('CORP\\');
    expect(extractCN('CN=CORP\\, O=Example')).not.toBe('CORP, O=Example');
  });

  it('still finds the common name behind a trailing backslash', () => {
    // The same defect in the position an ordinary certificate authority
    // produces. "O=" sits ahead of "CN=", so the swallowed component was the
    // common name itself and the reader fell all the way back to the subject.
    expect(extractCN('O=CORP\\, CN=leaf.example.com')).toBe('leaf.example.com');
  });

  it('reads the RFC 4514 spelling as literal backslashes', () => {
    // The deliberate behaviour change of issue #296, and the inverse of what the
    // C# side asserted before it. MockAdcsClient rendered this dialect through
    // BouncyCastle until PR #293 moved it onto X509Certificate2, and reading two
    // dialects was never free: the rule that decodes an escaped comma here is
    // the rule that swallows a component boundary above.
    expect(extractCN('CN=evil\\, O=Trusted Corp, O=Real Org')).toBe('evil\\');
  });

  it('treats an equals sign inside a quoted value as part of the name', () => {
    expect(extractCN('CN="a=b", O=Example')).toBe('a=b');
  });

  it('finds a common name after a multi-valued relative distinguished name', () => {
    // Plus separates the parts of one relative distinguished name, and a common
    // name sitting after one is still a common name.
    expect(extractCN('OU=IT+CN=leaf.example.com, O=Example')).toBe('leaf.example.com');
  });

  it('skips an empty common name so a real one later still reads', () => {
    expect(extractCN('CN=, OU=IT, CN=leaf.example.com')).toBe('leaf.example.com');
    expect(extractCN('CN=   , OU=IT, CN=leaf.example.com')).toBe('leaf.example.com');
  });

  it('keeps the spacing a quoted value chose to keep', () => {
    // Quoting is how CertNameToStr preserves a leading or trailing space, so
    // trimming after decoding would undo the reason for the quotes.
    expect(extractCN('CN="  spaced  ", O=Example')).toBe('  spaced  ');
  });

  it('skips the sanitizer truncation marker rather than reading it as a value', () => {
    // CertificateTextSanitizer stores an over-long subject as "<CN rdn>, …".
    // The marker is a component with no equals sign.
    expect(extractCN('CN=leaf.example.com, …')).toBe('leaf.example.com');
    expect(extractCN('CN=CORP\\, …')).toBe('CORP\\');
  });
});

describe('certificateDisplayName', () => {
  it('prefers the common name, then the first SAN, then the request number', () => {
    expect(
      certificateDisplayName({ subject: 'CN=leaf.example.com, O=Example' }),
    ).toBe('leaf.example.com');
    expect(
      certificateDisplayName({ subject: '', subjectAlternativeNames: 'dns:a.example.com,dns:b' }),
    ).toBe('a.example.com');
    expect(certificateDisplayName({ subject: '', requestId: 42 })).toBe('Request 42');
  });

  it('carries a trailing backslash through to the displayed name', () => {
    // The end of the chain issue #296 broke: this is the string the inventory
    // cell, the detail heading and the revoke dialog's typed confirmation all
    // show.
    expect(certificateDisplayName({ subject: 'CN=CORP\\, O=Example' })).toBe('CORP\\');
  });
});
