package eu.exeris.caps.federatedlogin.api.exception;

/**
 * Thrown when a stored flow state exists but cannot be opened: it names an unknown key, fails
 * authentication, or is malformed. The stored state is left in place, so a node that holds the right
 * key can still complete the flow.
 *
 * @since 0.1.0
 */
public final class FlowStateUnreadableException extends InvalidStateException {

    public FlowStateUnreadableException(String message) {
        super(message);
    }

    public FlowStateUnreadableException(String message, Throwable cause) {
        super(message, cause);
    }
}
