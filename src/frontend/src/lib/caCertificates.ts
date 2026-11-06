/**
 * The problem type the server answers when the CA refuses the service a read
 * (issue #476). It shares the 503 status with an outage, which is why the type
 * and not the status decides what the settings card says.
 */
export const CA_ACCESS_DENIED_PROBLEM = 'https://ducksinarow.dev/problems/ca-access-denied';

/** The parts of a failed request the CA certificates card reads. */
export interface ChainLoadFailure {
  status?: number;
  problemType?: string;
  problemDetail?: string;
}

/**
 * What the CA certificates card says when the chain did not load.
 *
 * A refusal comes first. It answers 503 like an outage, but no retry fixes it,
 * and its detail names the right to grant, so telling the administrator to try
 * again shortly would send them the wrong way. Before issue #476 a refusal
 * answered 500 and reached the last sentence below.
 */
export function describeChainLoadFailure(failure: ChainLoadFailure | undefined): string {
  if (failure?.problemType === CA_ACCESS_DENIED_PROBLEM) {
    // || rather than ??, so an empty detail falls back too rather than
    // rendering a blank notice.
    return failure.problemDetail ||
      'The certificate authority refused this server its certificate chain. Check the service log.';
  }
  if (failure?.status === 503) {
    return 'The certificate authority is unavailable. Try again shortly.';
  }
  return 'The CA certificate chain could not be loaded. Check the service log.';
}
