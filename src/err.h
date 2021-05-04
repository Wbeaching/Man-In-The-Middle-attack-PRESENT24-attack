#define ERR_INVALID_RUN_CMD         0
#define ERR_INVALID_OPTION          1
#define ERR_IVALID_ENCRYPTION_CMD   2
#define ERR_INVALID_DECRYPTION_CMD  3
#define ERR_INVALID_ATTACK_CMD      4
#define ERR_INVALID_ARG_SIZE        5
#define ERR_INVALID_CHAR            6

/**
 * Prints useful information to the terminal.
 */
void info();

/**
 * Prints warning information to the terminal.
 */
void warn();

/**
 * Prints error number information to the terminal.
 * @param nb_err The number of the error.
 */
void err(size_t nb_err);

