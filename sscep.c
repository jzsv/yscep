/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* Main routine */

#include "sscep.h"

int doSCEP() {

	int c, host_port = 80, count = 1;
	char *host_name, *p, *dir_name = NULL;
	char http_string[16384];
	struct http_reply reply;
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];
	struct scep scep_t;
	FILE *fp = NULL;
	BIO *bp;

	/*
	 * Check argument logic.
	 */
	if (!c_flag) {
		if (operation_flag == SCEP_OPERATION_GETCA) {
			fprintf(stderr, "%s: missing CA certificate filename (-c)\n",
					pname);
			exit(SCEP_PKISTATUS_ERROR);
		} else {
			fprintf(stderr, "%s: missing CA certificate (-c)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
	}
	if (operation_flag == SCEP_OPERATION_ENROLL) {
		if (!k_flag) {
			fprintf(stderr, "%s: missing private key (-k)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		if (!r_flag) {
			fprintf(stderr, "%s: missing request (-r)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);

		}
		if (!l_flag) {
			fprintf(stderr, "%s: missing local cert (-l)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		/* Set polling limits */
		if (!n_flag)
			n_num = MAX_POLL_COUNT;
		if (!t_flag)
			t_num = POLL_TIME;
		if (!T_flag)
			T_num = MAX_POLL_TIME;
	}
	if (operation_flag == SCEP_OPERATION_GETCERT) {
		if (!l_flag) {
			fprintf(stderr, "%s: missing local cert (-l)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		if (!s_flag) {
			fprintf(stderr, "%s: missing serial no (-s)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		if (!w_flag) {
			fprintf(stderr, "%s: missing cert file (-w)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		if (!k_flag) {
			fprintf(stderr, "%s: missing private key (-k)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
	}
	if (operation_flag == SCEP_OPERATION_GETCRL) {
		if (!l_flag) {
			fprintf(stderr, "%s: missing local cert (-l)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		if (!w_flag) {
			fprintf(stderr, "%s: missing crl file (-w)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		if (!k_flag) {
			fprintf(stderr, "%s: missing private key (-k)\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
	}

	/* Break down the URL */
	if (!u_flag) {
		fprintf(stderr, "%s: missing URL (-u)\n", pname);
		exit(SCEP_PKISTATUS_ERROR);
	}
	if (strncmp(url_char, "http://", 7) && !p_flag) {
		fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
		exit(SCEP_PKISTATUS_ERROR);
	}
	if (p_flag) {
		host_name = strdup(p_char);
		dir_name = url_char;
	}

	/* Break down the URL */
	if (!u_flag) {
		fprintf(stderr, "%s: missing URL (-u)\n", pname);
		exit(SCEP_PKISTATUS_ERROR);
	}
	if (strncmp(url_char, "http://", 7) && !p_flag) {
		fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
		exit(SCEP_PKISTATUS_ERROR);
	}
	if (p_flag) {
		host_name = strdup(p_char);
		dir_name = url_char;
	} else if (!(host_name = strdup(url_char + 7)))
		error_memory();
	p = host_name;
	c = 0;
	while (*p != '\0') {
		if (*p == '/' && !p_flag && !c) {
			*p = '\0';
			if (*(p + 1))
				dir_name = p + 1;
			c = 1;
		}
		if (*p == ':') {
			*p = '\0';
			if (*(p + 1))
				host_port = atoi(p + 1);
		}
		p++;
	}
	if (!dir_name) {
		fprintf(stderr, "%s: illegal URL\n", pname);
		exit(SCEP_PKISTATUS_ERROR);
	}
	if (host_port < 1 || host_port > 65550) {
		fprintf(stderr, "%s: illegal port number %d\n", pname, host_port);
		exit(SCEP_PKISTATUS_ERROR);
	}
	if (v_flag) {
		fprintf(stdout, "%s: hostname: %s\n", pname, host_name);
		fprintf(stdout, "%s: directory: %s\n", pname, dir_name);
		fprintf(stdout, "%s: port: %d\n", pname, host_port);
	}

	/* Check algorithms */
	if (!E_flag) {
		enc_alg = (EVP_CIPHER *) EVP_des_cbc();
	} else if (!strncmp(E_char, "blowfish", 8)) {
		enc_alg = (EVP_CIPHER *) EVP_bf_cbc();
	} else if (!strncmp(E_char, "des", 3)) {
		enc_alg = (EVP_CIPHER *) EVP_des_cbc();
	} else if (!strncmp(E_char, "3des", 4)) {
		enc_alg = (EVP_CIPHER *) EVP_des_ede3_cbc();
	} else if (!strncmp(E_char, "aes128", 4)) {
		enc_alg = (EVP_CIPHER *) EVP_aes_128_cbc();
	} else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n", pname, E_char);
		exit(SCEP_PKISTATUS_ERROR);
	}
	if (!S_flag) {
		sig_alg = (EVP_MD *) EVP_md5();
	} else if (!strncmp(S_char, "md5", 3)) {
		sig_alg = (EVP_MD *) EVP_md5();
	} else if (!strncmp(S_char, "sha1", 4)) {
		sig_alg = (EVP_MD *) EVP_sha1();
	} else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n", pname, S_char);
		exit(SCEP_PKISTATUS_ERROR);
	}
	/* Fingerprint algorithm */
	if (!F_flag) {
		fp_alg = (EVP_MD *) EVP_md5();
	} else if (!strncmp(F_char, "md5", 3)) {
		fp_alg = (EVP_MD *) EVP_md5();
	} else if (!strncmp(F_char, "sha1", 4)) {
		fp_alg = (EVP_MD *) EVP_sha1();
	} else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n", pname, F_char);
		exit(SCEP_PKISTATUS_ERROR);
	}

	/*
	 * Switch to operation specific code
	 */
	switch (operation_flag) {
	case SCEP_OPERATION_GETCA:
		if (v_flag)
			fprintf(stdout, "%s: SCEP_OPERATION_GETCA\n", pname);

		/* Set CA identifier */
		if (!i_flag)
			i_char = CA_IDENTIFIER;

		/* Forge the HTTP message */
		snprintf(http_string, sizeof(http_string),
				"GET %s%s?operation=GetCACert&message=%s "
						"HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
				i_char);
		printf("%s: requesting CA certificate\n", pname);
		if (d_flag)
			fprintf(stdout, "%s: scep msg: %s", pname, http_string);
		/*
		 * Send http message.
		 * Response is written to http_response struct "reply".
		 */
		reply.payload = NULL;
		if ((c = send_msg(&reply, http_string, host_name, host_port,
				operation_flag)) == 1) {
			fprintf(stderr, "%s: error while sending "
					"message\n", pname);
			exit(SCEP_PKISTATUS_NET);
		}
		if (reply.payload == NULL) {
			fprintf(stderr, "%s: no data, perhaps you "
					"should define CA identifier (-i)\n", pname);
			exit(SCEP_PKISTATUS_SUCCESS);
		}
		printf("%s: valid response from server\n", pname);
		if (reply.type == SCEP_MIME_GETCA_RA) {
			/* XXXXXXXXXXXXXXXXXXXXX chain not verified */
			write_ca_ra(&reply);
		}
		/* Read payload as DER X.509 object: */
		bp = BIO_new_mem_buf(reply.payload, reply.bytes);
		cacert = d2i_X509_bio(bp, NULL);

		/* Read and print certificate information */
		if (!X509_digest(cacert, fp_alg, md, &n)) {
			ERR_print_errors_fp(stderr);
			exit(SCEP_PKISTATUS_ERROR);
		}
		printf("%s: %s fingerprint: ", pname, OBJ_nid2sn(EVP_MD_type(fp_alg)));
		for (c = 0; c < (int) n; c++) {
			printf("%02X%c", md[c], (c + 1 == (int) n) ? '\n' : ':');
		}

		/* Write PEM-formatted file: */
		if (!(fp = fopen(c_char, "w"))) {
			fprintf(stderr, "%s: cannot open CA file for "
					"writing\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
		if (PEM_write_X509(fp, cacert) != 1) {
			fprintf(stderr, "%s: error while writing CA "
					"file\n", pname);
			ERR_print_errors_fp(stderr);
			exit(SCEP_PKISTATUS_ERROR);
		}
		printf("%s: CA certificate written as %s\n", pname, c_char);
		(void) fclose(fp);
		pkistatus = SCEP_PKISTATUS_SUCCESS;
		break;

	case SCEP_OPERATION_GETCERT:
	case SCEP_OPERATION_GETCRL:
		/* Read local certificate */
		if (!l_flag) {
			fprintf(stderr, "%s: missing local cert (-l)\n", pname);
			exit(SCEP_PKISTATUS_FILE);
		}
		read_cert(&localcert, l_char);

	case SCEP_OPERATION_ENROLL:

		create_key_csr();

		/*
		 * Read in CA cert, private key and certificate
		 * request in global variables.
		 */
		read_ca_cert();

		if (!k_flag) {
			fprintf(stderr, "%s: missing private key (-k)\n", pname);
			exit(SCEP_PKISTATUS_FILE);
		}
		read_key(&rsa, k_char);

		if ((K_flag && !O_flag) || (!K_flag && O_flag)) {
			fprintf(stderr, "%s: -O also requires -K (and vice-versa)\n",
					pname);
			exit(SCEP_PKISTATUS_FILE);
		}

		if (K_flag) {
			read_key(&renewal_key, K_char);
		}

		if (O_flag) {
			read_cert(&renewal_cert, O_char);
		}

		if (operation_flag == SCEP_OPERATION_ENROLL)
			read_request();

		/*
		 * Create a new SCEP transaction and self-signed
		 * certificate based on cert request
		 */
		if (v_flag)
			fprintf(stdout, "%s: new transaction\n", pname);
		new_transaction(&scep_t);
		if (operation_flag != SCEP_OPERATION_ENROLL)
			goto not_enroll;
		if (v_flag)
			fprintf(stdout, "%s: generating selfsigned "
					"certificate\n", pname);

		if (!O_flag)
			new_selfsigned(&scep_t);
		else {
			/* Use existing certificate */
			scep_t.signercert = renewal_cert;
			scep_t.signerkey = renewal_key;
		}

		/* Write the selfsigned certificate if requested */
		if (L_flag) {
			/* Write PEM-formatted file: */
			if (!(fp = fopen(L_char, "w"))) {
				fprintf(stderr, "%s: cannot open "
						"file for writing\n", pname);
				exit(SCEP_PKISTATUS_ERROR);
			}
			if (PEM_write_X509(fp, scep_t.signercert) != 1) {
				fprintf(stderr, "%s: error while "
						"writing certificate file\n", pname);
				ERR_print_errors_fp(stderr);
				exit(SCEP_PKISTATUS_ERROR);
			}
			printf("%s: selfsigned certificate written "
					"as %s\n", pname, L_char);
			(void) fclose(fp);
		}
		/* Write issuer name and subject (GetCertInitial): */
		if (!(scep_t.ias_getcertinit->subject =
		X509_REQ_get_subject_name(request))) {
			fprintf(stderr, "%s: error getting subject "
					"for GetCertInitial\n", pname);
			ERR_print_errors_fp(stderr);
			exit(SCEP_PKISTATUS_ERROR);
		}
		not_enroll: if (!(scep_t.ias_getcertinit->issuer = X509_get_issuer_name(
				cacert))) {
			fprintf(stderr, "%s: error getting issuer "
					"for GetCertInitial\n", pname);
			ERR_print_errors_fp(stderr);
			exit(SCEP_PKISTATUS_ERROR);
		}
		/* Write issuer name and serial (GETC{ert,rl}): */
		scep_t.ias_getcert->issuer = scep_t.ias_getcertinit->issuer;
		scep_t.ias_getcrl->issuer = scep_t.ias_getcertinit->issuer;
		if (!(scep_t.ias_getcrl->serial = X509_get_serialNumber(cacert))) {
			fprintf(stderr, "%s: error getting serial "
					"for GetCertInitial\n", pname);
			ERR_print_errors_fp(stderr);
			exit(SCEP_PKISTATUS_ERROR);
		}
		/* User supplied serial number */
		if (s_flag) {
			if (!(ASN1_INTEGER_set(scep_t.ias_getcert->serial,
					(long) atoi(s_char)))) {
				fprintf(stderr, "%s: error converting "
						"serial\n", pname);
				ERR_print_errors_fp(stderr);
				exit(SCEP_PKISTATUS_ERROR);
			}
		}
		break;
	}
	switch (operation_flag) {
	case SCEP_OPERATION_ENROLL:
		if (v_flag)
			fprintf(stdout, "%s: SCEP_OPERATION_ENROLL\n", pname);
		/* Resum mode: set GetCertInitial */
		if (R_flag) {
			if (n_num == 0)
				exit(SCEP_PKISTATUS_SUCCESS);
			printf("%s: requesting certificate (#1)\n", pname);
			scep_t.request_type = SCEP_REQUEST_GETCERTINIT;
			count++;
		} else {
			printf("%s: sending certificate request\n", pname);
			scep_t.request_type = SCEP_REQUEST_PKCSREQ;
		}
		break;

	case SCEP_OPERATION_GETCERT:
		if (v_flag)
			fprintf(stdout, "%s: SCEP_OPERATION_GETCERT\n", pname);

		scep_t.request_type = SCEP_REQUEST_GETCERT;
		printf("%s: requesting certificate\n", pname);
		break;

	case SCEP_OPERATION_GETCRL:
		if (v_flag)
			fprintf(stdout, "%s: SCEP_OPERATION_GETCRL\n", pname);

		scep_t.request_type = SCEP_REQUEST_GETCRL;
		printf("%s: requesting crl\n", pname);
		break;
	}

	/* Enter polling loop */
	while (scep_t.pki_status != SCEP_PKISTATUS_SUCCESS) {
		/* create payload */
		pkcs7_wrap(&scep_t);

		/* URL-encode */
		p = url_encode(scep_t.request_payload, scep_t.request_len);

		/* Forge the HTTP message */
		snprintf(http_string, sizeof(http_string), "GET %s%s?operation="
				"PKIOperation&message="
				"%s HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name, p);

		if (d_flag)
			fprintf(stdout, "%s: scep msg: %s", pname, http_string);

		/* send http */
		reply.payload = NULL;
		if ((c = send_msg(&reply, http_string, host_name, host_port,
				operation_flag)) == 1) {
			fprintf(stderr, "%s: error while sending "
					"message\n", pname);
			exit(SCEP_PKISTATUS_NET);
		}
		/* Verisign Onsite returns strange reply...
		 * XXXXXXXXXXXXXXXXXXX */
		if ((reply.status == 200) && (reply.payload == NULL)) {
			/*
			 scep_t.pki_status = SCEP_PKISTATUS_PENDING;
			 break;
			 */
			exit(SCEP_PKISTATUS_ERROR);
		}
		printf("%s: valid response from server\n", pname);

		/* Check payload */
		scep_t.reply_len = reply.bytes;
		scep_t.reply_payload = reply.payload;
		pkcs7_unwrap(&scep_t);
		pkistatus = scep_t.pki_status;

		switch (scep_t.pki_status) {
		case SCEP_PKISTATUS_SUCCESS:
			break;
		case SCEP_PKISTATUS_PENDING:
			/* Check time limits */
			if (((t_num * count) >= T_num) || (count > n_num)) {
				exit(pkistatus);
			}
			scep_t.request_type =
			SCEP_REQUEST_GETCERTINIT;

			/* Wait for poll interval */
			if (v_flag)
				printf("%s: waiting for %d secs\n", pname, t_num);
			sleep(t_num);
			printf("%s: requesting certificate "
					"(#%d)\n", pname, count);

			/* Add counter */
			count++;
			break;

		case SCEP_PKISTATUS_FAILURE:

			/* Handle failure */
			switch (scep_t.fail_info) {
			case SCEP_FAILINFO_BADALG:
				exit(SCEP_PKISTATUS_BADALG);
			case SCEP_FAILINFO_BADMSGCHK:
				exit(SCEP_PKISTATUS_BADMSGCHK);
			case SCEP_FAILINFO_BADREQ:
				exit(SCEP_PKISTATUS_BADREQ);
			case SCEP_FAILINFO_BADTIME:
				exit(SCEP_PKISTATUS_BADTIME);
			case SCEP_FAILINFO_BADCERTID:
				exit(SCEP_PKISTATUS_BADCERTID);
				/* Shouldn't be there... */
			default:
				exit(SCEP_PKISTATUS_ERROR);
			}
		default:
			fprintf(stderr, "%s: unknown "
					"pkiStatus\n", pname);
			exit(SCEP_PKISTATUS_ERROR);
		}
	}
	/* We got SUCCESS, analyze the reply */
	switch (scep_t.request_type) {

	/* Local certificate */
	case SCEP_REQUEST_PKCSREQ:
	case SCEP_REQUEST_GETCERTINIT:
		write_local_cert(&scep_t);
		break;

		/* Other end entity certificate */
	case SCEP_REQUEST_GETCERT:
		write_other_cert(&scep_t);
		break;

		break;
		/* CRL */
	case SCEP_REQUEST_GETCRL:
		write_crl(&scep_t);
		break;
	}
	return (pkistatus);
}
