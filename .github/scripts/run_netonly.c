/*
 * Tiny helper for CI tests that need SSPI to acquire network credentials
 * without logging the runner into a Kerberos realm.
 */

#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static wchar_t *
widen(const char *str)
{
	int len;
	wchar_t *out;

	len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	if (len <= 0)
		return NULL;
	out = calloc((size_t)len, sizeof(wchar_t));
	if (out == NULL)
		return NULL;
	if (MultiByteToWideChar(CP_UTF8, 0, str, -1, out, len) <= 0) {
		free(out);
		return NULL;
	}
	return out;
}

static const char *
env_value(const char *name)
{
	const char *value = getenv(name);

	return value != NULL && value[0] != '\0' ? value : NULL;
}

static int
split_user(const char *user, const char *domain_env, char *user_only,
    size_t user_len, char *domain_only, size_t domain_len)
{
	char *slash;

	if (snprintf(user_only, user_len, "%s", user) < 0 ||
	    strlen(user_only) >= user_len)
		return 1;
	domain_only[0] = '\0';

	slash = strchr(user_only, '\\');
	if (slash != NULL) {
		*slash = '\0';
		if (snprintf(domain_only, domain_len, "%s", user_only) < 0 ||
		    strlen(domain_only) >= domain_len)
			return 1;
		memmove(user_only, slash + 1, strlen(slash + 1) + 1);
	} else if (domain_env != NULL && domain_env[0] != '\0') {
		if (snprintf(domain_only, domain_len, "%s", domain_env) < 0 ||
		    strlen(domain_only) >= domain_len)
			return 1;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	const char *user, *password, *domain_env, *cmdline, *cwd_env;
	char user_only[256], domain_only[256];
	wchar_t cwd[MAX_PATH];
	wchar_t *wuser = NULL, *wdomain = NULL, *wpassword = NULL;
	wchar_t *wcmdline = NULL, *wcwd = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD exit_code = 1;
	int ret = 1;

	if (argc != 3 || strcmp(argv[1], "--cmdline") != 0) {
		fprintf(stderr, "usage: run_netonly.exe --cmdline COMMAND\n");
		return 2;
	}
	cmdline = argv[2];
	user = env_value("RUN_NETONLY_USER");
	password = env_value("RUN_NETONLY_PASSWORD");
	domain_env = env_value("RUN_NETONLY_DOMAIN");
	cwd_env = env_value("RUN_NETONLY_CWD");
	if (user == NULL || password == NULL) {
		fprintf(stderr,
		    "set RUN_NETONLY_USER and RUN_NETONLY_PASSWORD\n");
		return 2;
	}
	if (split_user(user, domain_env, user_only, sizeof(user_only),
	    domain_only, sizeof(domain_only)) != 0) {
		fprintf(stderr, "user/domain value is too long\n");
		goto done;
	}

	wuser = widen(user_only);
	wpassword = widen(password);
	wcmdline = widen(cmdline);
	if (domain_only[0] != '\0')
		wdomain = widen(domain_only);
	if (cwd_env != NULL)
		wcwd = widen(cwd_env);
	else if (GetCurrentDirectoryW(MAX_PATH, cwd) != 0)
		wcwd = cwd;

	if (wuser == NULL || wpassword == NULL || wcmdline == NULL ||
	    (domain_only[0] != '\0' && wdomain == NULL) || wcwd == NULL) {
		fprintf(stderr, "failed to allocate process arguments\n");
		goto done;
	}

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	if (!CreateProcessWithLogonW(wuser, wdomain, wpassword,
	    LOGON_NETCREDENTIALS_ONLY, NULL, wcmdline, CREATE_NO_WINDOW, NULL,
	    wcwd, &si, &pi)) {
		fprintf(stderr, "CreateProcessWithLogonW failed: %lu\n",
		    GetLastError());
		goto done;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	if (!GetExitCodeProcess(pi.hProcess, &exit_code))
		exit_code = 1;
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	ret = (int)exit_code;

done:
	free(wuser);
	free(wdomain);
	free(wpassword);
	free(wcmdline);
	if (wcwd != NULL && wcwd != cwd)
		free(wcwd);
	return ret;
}
