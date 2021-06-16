#ifndef LPP_LOGPICKER_STATE_HPP
#define LPP_LOGPICKER_STATE_HPP

enum logpicker_state_t {
    IDLE, // Initial State
    // States on the left side of the state machine
    // Leader states
    STARTED_LP_RUN,
    SENT_COMMIT_REQUEST,
    RECEIVED_COMMIT_REPLY,
    SENT_REVEAL_REQUEST,
    RECEIVED_REVEAL_REPLY,
    SENT_PROOF_REQUEST,
    RECEIVED_PROOF_REPLY,
    // States on the right side of the state machine
    // Regular instance states
    RECEIVED_COMMIT_REQUEST,
    SENT_COMMIT_REPLY,
    RECEIVED_REVEAL_REQUEST,
    SENT_REVEAL_REPLY,
    RECEIVED_PROOF_REQUEST,
    SENT_PROOF_REPLY,
    FINISHED, // LP run completed successfully
    ERROR // Error during execution
};
#endif
