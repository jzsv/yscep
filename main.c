/*
 *  main.c
 *
 *  Created on: May 22, 2014
 *  Author: jz
 */

/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* Main routine */

#include "sscep.h"

static char *
handle_serial(char * serial) {
	int hex = NULL != strchr(serial, ':');

	/* Convert serial to a decimal serial when input is
	 a hexidecimal representation of the serial */
	if (hex) {
		unsigned int i, ii;
		char *tmp_serial = (char*) calloc(strlen(serial) + 1, 1);

		for (i = 0, ii = 0; '\0' != serial[i]; i++) {
			if (':' != serial[i])
				tmp_serial[ii++] = serial[i];
		}
		serial = tmp_serial;
	} else {
		unsigned int i;
		for (i = 0; !hex && '\0' != serial[i]; i++)
			hex = 'a' == serial[i] || 'b' == serial[i] || 'c' == serial[i]
					|| 'd' == serial[i] || 'e' == serial[i] || 'f' == serial[i];
	}

	if (hex) {
		ASN1_INTEGER* ai;
		BIGNUM *ret;
		BIO* in = BIO_new_mem_buf(serial, -1);
		char buf[1025];
		ai = ASN1_INTEGER_new();
		if (ai == NULL)
			return NULL;
		if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
			return NULL;
		}
		ret = ASN1_INTEGER_to_BN(ai, NULL);
		if (ret == NULL) {
			return NULL;
		} else {
			serial = BN_bn2dec(ret);
		}
	}

	return serial;
} /* handle_serial */

int main(int argc, char **argv) {

	int c;

	/* Initialize scep layer */
	init_scep();

	/* Set program name */
	pname = argv[0];

	/* Define signal trap */
	(void) signal(SIGALRM, catchalarm);

	/* Set timeout */
	timeout = TIMEOUT;

	/* Check operation parameter */
	if (!argv[1]) {
		usage();
	} else if (!strncmp(argv[1], "getca", 5)) {
		operation_flag = SCEP_OPERATION_GETCA;
	} else if (!strncmp(argv[1], "enroll", 6)) {
		operation_flag = SCEP_OPERATION_ENROLL;
	} else if (!strncmp(argv[1], "getcert", 7)) {
		operation_flag = SCEP_OPERATION_GETCERT;
	} else if (!strncmp(argv[1], "getcrl", 6)) {
		operation_flag = SCEP_OPERATION_GETCRL;
	} else {
		fprintf(stderr, "%s: missing or illegal operation parameter\n",
				argv[0]);
		usage();
	}
	/* Skip first parameter and parse the rest of the command */
	optind++;
	while ((c = getopt(argc, argv,
			"c:de:E:f:F:i:k:K:l:L:n:O:p:P:r:Rs:S:t:T:u:vw:x:X:I")) != -1)

		switch (c) {
		case 'c':
			c_flag = 1;
			c_char = optarg;
			break;
		case 'd':
			d_flag = 1;
			break;
		case 'e':
			e_flag = 1;
			e_char = optarg;
			break;
		case 'E':
			E_flag = 1;
			E_char = optarg;
			break;
		case 'F':
			F_flag = 1;
			F_char = optarg;
			break;
		case 'f':
			f_flag = 1;
			f_char = optarg;
			break;
		case 'i':
			i_flag = 1;
			i_char = optarg;
			break;
		case 'I':
			/* Read ALL configuration from standard input */
			I_flag = 1;
			break;
		case 'k':
			k_flag = 1;
			k_char = optarg;
			break;
		case 'K':
			K_flag = 1;
			K_char = optarg;
			break;
		case 'l':
			l_flag = 1;
			l_char = optarg;
			break;
		case 'L':
			L_flag = 1;
			L_char = optarg;
			break;
		case 'n':
			n_flag = 1;
			n_num = atoi(optarg);
			break;
		case 'O':
			O_flag = 1;
			O_char = optarg;
			break;
		case 'p':
			p_flag = 1;
			p_char = optarg;
			break;
		case 'P':
			P_flag = 1;
			P_char = optarg;
			break;
		case 'r':
			r_flag = 1;
			r_char = optarg;
			break;
		case 'R':
			R_flag = 1;
			break;
		case 's':
			s_flag = 1;
			/*s_char = optarg;*/
			s_char = handle_serial(optarg);
			break;
		case 'S':
			S_flag = 1;
			S_char = optarg;
			break;
		case 't':
			t_flag = 1;
			t_num = atoi(optarg);
			break;
		case 'T':
			T_flag = 1;
			T_num = atoi(optarg);
			break;
		case 'u':
			u_flag = 1;
			url_char = optarg;
			break;
		case 'v':
			v_flag = 1;
			break;
		case 'w':
			w_flag = 1;
			w_char = optarg;
			break;
		case 'x':
			kg_flag = 1;
			keygen_char = optarg;
			break;
		case 'X':
			cg_flag = 1;
			csrgen_char = optarg;
			break;
		default:
			printf("argv: %s\n", argv[optind]);
			usage();
		}
	argc -= optind;
	argv += optind;

	/* If we debug, include verbose messages also */
	if (d_flag)
		v_flag = 1;

	if (v_flag)
		fprintf(stdout, "%s: starting yscep, version %s\n", pname, VERSION);

	if (f_flag)
		init_config(f_char);

	if (I_flag) {
		fprintf(stdout, "reading config from stdin\n");
		read_config(stdin);
	}

	if (!d_flag) atexit(cleanup);

	return doSCEP();

}

void usage() {
	fprintf(stdout, "\nYscep version %s - significant change from sscep by jz@\n\n", VERSION);
	fprintf(stdout,
			"Usage: %s OPERATION [OPTIONS]\n"
					"\nAvailable OPERATIONs:\n"
					"  getca             Get CA/RA certificate(s)\n"
					"  enroll            Enroll certificate\n"
					"  getcert           Query certificate\n"
					"  getcrl            Query CRL\n"
					"\nConfiguration OPTIONs:\n"
					"  -I                Read config from stdin\n"
					"  -f <file>         Read config from file\n\n"
			     /* "\nGeneral OPTIONS\n"
					"  -u <url>          SCEP server URL\n"
					"  -p <host:port>    Use proxy server at host:port\n"
					"  -c <file>         CA certificate file (write if OPERATION is getca)\n"
					"  -E <name>         PKCS#7 encryption algorithm (des|3des|blowfish)\n"
					"  -S <name>         PKCS#7 signature algorithm (md5|sha1)\n"
					"  -v                Verbose operation\n"
					"  -d                Debug (even more verbose operation)\n"
					"\nOPTIONS for OPERATION getca are\n"
					"  -i <string>       CA identifier string\n"
					"  -F <name>         Fingerprint algorithm\n"
					"\nOPTIONS for OPERATION enroll are\n"
					"  -P <ChallengePassword>    scep enrollment token\n"
					"  -k <file>         Private key file\n"
					"  -r <file>         Certificate request file\n"
					"  -K <file>         Signature private key file, use with -O\n"
					"  -O <file>         Signature certificate (used instead of self-signed)\n"
					"  -l <file>         Write enrolled certificate in file\n"
					"  -e <file>         Use different CA cert for encryption\n"
					"  -L <file>         Write selfsigned certificate in file\n"
					"  -t <secs>         Polling interval in seconds\n"
					"  -T <secs>         Max polling time in seconds\n"
					"  -n <count>        Max number of GetCertInitial requests\n"
					"  -R                Resume interrupted enrollment\n"
					"  -x <Keygen cmd>   Command for key generation\n"
					"  -X <CSRgen cmd>   Command for CSR generation\n"
					"\nOPTIONS for OPERATION getcert are\n"
					"  -k <file>         Private key file\n"
					"  -l <file>         Local certificate file\n"
					"  -s <number>       Certificate serial number\n"
					"  -w <file>         Write certificate in file\n"
					"\nOPTIONS for OPERATION getcrl are\n"
					"  -k <file>         Private key file\n"
					"  -l <file>         Local certificate file\n"
					"  -w <file>         Write CRL in file\n\n"*/, pname);

	exit(0);
}

void catchalarm(int signo) {
	fprintf(stderr, "%s: connection timed out\n", pname);
	exit(SCEP_PKISTATUS_TIMEOUT);
}

