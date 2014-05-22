/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* Configuration file initialization */

#include <openssl/conf.h>
#include <openssl/err.h>

#include "sscep.h"

void handle_error(char *file, int lineno, char *msg) {
	fprintf(stderr, "%s: %s %d %s ", pname, file, lineno, msg);
	ERR_print_errors_fp(stderr);
	fprintf(stderr, "\n");
}

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

#define SCEP_SECTION "yscep"

#define SSCEP_TMP_CONF_FILE "./yscep.tmp"

#define STDIN_EOF	"#EOF#"

static CONF *conf = NULL;

static char *tmp_conf_fname = NULL;

/* called on program exit */
void cleanup()
{
	if (I_flag) {
		remove(tmp_conf_fname);
	}

	fini_config();
}

void read_config(FILE *fp)
{

	char *tmp_conf_fname = getenv("SSCEP_TMP_CONF_FILE");

	if (tmp_conf_fname == NULL) tmp_conf_fname = SSCEP_TMP_CONF_FILE;

	FILE *fp2 = fopen(tmp_conf_fname, "w");

	if (fp2 == NULL) {
		fprintf(stderr, "%s: error opening %s for write access\n", pname, tmp_conf_fname);
		return;
	}

	char buff[4096];

	for (;;) {
		if (fgets(buff, 4096, fp) == NULL) break;
		if (fputs(buff, fp2) < 0) {
			fprintf(stderr, "%s: error writting to file %s\n", pname, tmp_conf_fname);
			break;
		}
		if (!strncmp(buff, STDIN_EOF, strlen(STDIN_EOF))) break;
	}

	fclose(fp2);

	init_config(tmp_conf_fname);

        f_char = tmp_conf_fname;
}

void fini_config() {
	if (conf != NULL)
		NCONF_free(conf);
}

void init_config(char *file) {
	long err = 0;
	char *str;

	if (conf == NULL)
		conf = NCONF_new(NCONF_default());

	if (!NCONF_load(conf, file, &err)) {
		if (err != 0)
			handle_error(file, err, "error loading");
		else
			fprintf(stderr, "%s: unknown error reading config from %s\n", pname,
					file);
		return;
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "Debug"))) {
		if (!strncmp(str, "yes", 3))
			d_flag = 1;
		else
			d_flag = 0;
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "Verbose"))) {
		if (!strncmp(str, "yes", 3))
			v_flag = 1;
		else
			v_flag = 0;
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "CACertFile"))) {
		if (!c_flag) {
			c_flag = 1;
			c_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "CAIdentifier"))) {
		if (!i_flag) {
			i_flag = 1;
			i_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "CertReqFile"))) {
		if (!r_flag) {
			r_flag = 1;
			r_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "EncCertFile"))) {
		if (!e_flag) {
			e_flag = 1;
			e_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "EncAlgorithm"))) {
		if (!E_flag) {
			E_flag = 1;
			E_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "FingerPrint"))) {
		if (!F_flag) {
			F_flag = 1;
			F_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "GetCertFile"))
			&& operation_flag == SCEP_OPERATION_GETCERT) {
		if (!w_flag) {
			w_flag = 1;
			w_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "GetCrlFile"))
			&& operation_flag == SCEP_OPERATION_GETCRL) {
		if (!w_flag) {
			w_flag = 1;
			w_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "GetCertSerial"))) {
		if (!s_flag) {
			s_flag = 1;
			s_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "LocalCertFile"))) {
		if (!l_flag) {
			l_flag = 1;
			l_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "SignCertFile"))) {
		if (!O_flag) {
			O_flag = 1;
			O_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "PrivateKeyFile"))) {
		if (!k_flag) {
			k_flag = 1;
			k_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "SignKeyFile"))) {
		if (!K_flag) {
			K_flag = 1;
			K_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "SelfSignedFile"))) {
		if (!L_flag) {
			L_flag = 1;
			L_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "SigAlgorithm"))) {
		if (!S_flag) {
			S_flag = 1;
			S_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "URL"))) {
		if (!u_flag) {
			u_flag = 1;
			url_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "Proxy"))) {
		if (!p_flag) {
			p_flag = 1;
			p_char = str;
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "KeyGenCmd"))) {
		if (!kg_flag) {
			keygen_char = str;
		} else {
			//TODO
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "CsrGenCmd"))) {
		if (!cg_flag) {
			csrgen_char = str;
		} else {
			//TODO
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "MaxPollCount"))) {
		if (!n_flag) {
			n_flag = 1;
			n_num = atoi(str);
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "MaxPollTime"))) {
		if (!T_flag) {
			T_flag = 1;
			T_num = atoi(str);
		}
	}

	if ((str = NCONF_get_string(conf, SCEP_SECTION, "PollInterval"))) {
		if (!t_flag) {
			t_flag = 1;
			t_num = atoi(str);
		}
	}

	NCONF_dump_fp(conf, stderr);

	return;
}

void error_memory() {
	fprintf(stderr, "%s: memory allocation failure, errno: %d\n", pname, errno);
	exit(1);
}

/* Credit to Laird Shaw, copied from http://creativeandcritical.net/str-replace-c 
 */
char *replace_str(const char *str, const char *old, const char *new) {
	if (str == NULL || old == NULL || new == NULL)
		return NULL;

	if (strstr(str, old) == NULL)
		return strdup(str); /* no pattern return a couple of itself */

	char *ret, *r;
	const char *p, *q;
	size_t oldlen = strlen(old);
	size_t count, retlen, newlen = strlen(new);

	if (oldlen != newlen) {
		for (count = 0, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
			count++;
		/* this is undefined if p - str > PTRDIFF_MAX */
		retlen = p - str + strlen(p) + count * (newlen - oldlen);
	} else
		retlen = strlen(str);

	if ((ret = malloc(retlen + 1)) == NULL)
		return NULL;

	for (r = ret, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen) {
		/* this is undefined if q - p > PTRDIFF_MAX */
		ptrdiff_t l = q - p;
		memcpy(r, p, l);
		r += l;
		memcpy(r, new, newlen);
		r += newlen;
	}

	strcpy(r, p);

	return ret;
}

void create_key_csr() {
	/*
	 KeyGenCmd = "openssl genrsa -out $PrivateKeyFile 2048"
	 #KeyGenCmd = openssl ecparam -name secp256k1 -genkey -noout -out $PrivateKeyFile
	 CsrGenCmd = "openssl req -new -key $PrivateKeyFile -out $CertReqFile -config $ConfigFile -reqexts v3_req"
	 */

	/* create key  */

	if (keygen_char != NULL) {

		fprintf(stderr, "%s: Keygen cmd (raw): <%s>\n", pname, keygen_char);

		char *ptr = replace_str(keygen_char, "$PrivateKeyFile", k_char);

		fprintf(stderr, "%s: Keygen cmd: <%s>\n", pname, ptr);

		int ret = system(ptr);

		if (ret < 0) {
			fprintf(stderr, "%s: executing keygen cmd <%s> failed\n", pname,
					ptr);
		}

		free(ptr);

	} else {
		/* key must have already generated, hence this cmd is not set. */
	}

	/* create csr */

	if (csrgen_char != NULL) {

		fprintf(stderr, "%s: Csrgen cmd (raw): <%s>\n", pname, csrgen_char);

		char *ptr = replace_str(csrgen_char, "$PrivateKeyFile", k_char);
		char *tmp = ptr;

		ptr = replace_str(ptr, "$CertReqFile", r_char);
		free(tmp);
		tmp = ptr;

		ptr = replace_str(ptr, "$ConfigFile", f_char);
		free(tmp);

		fprintf(stderr, "%s: Csrgen cmd: <%s>\n", pname, ptr);

		int ret = system(ptr);

		if (ret < 0) {
			fprintf(stderr, "%s: executing csrgen cmd <%s> failed\n", pname,
					ptr);
		}

		free(ptr);

	} else {
		/* csr must have already generated, hence this cmd is not set. */
	}
}


