/** Ignore auth replies superseded by another refresh or a logout. */
export function shouldApplySessionResponse(requestId: number, currentId: number, signingOut = false): boolean {
  return requestId === currentId && !signingOut;
}
