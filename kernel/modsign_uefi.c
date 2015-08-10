#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/efi.h>
#include <linux/slab.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include "module-internal.h"

static __init int check_ignore_db(void)
{
	efi_status_t status;
	unsigned int db = 0;
	unsigned long size = sizeof(db);
	efi_guid_t guid = EFI_SHIM_LOCK_GUID;

	/* Check and see if the MokIgnoreDB variable exists.  If that fails
	 * then we don't ignore DB.  If it succeeds, we do.
	 */
	status = efi.get_variable(L"MokIgnoreDB", &guid, NULL, &size, &db);
	if (status != EFI_SUCCESS)
		return 0;

	return 1;
}

static __init void *get_cert_list(efi_char16_t *name, efi_guid_t *guid, unsigned long *size)
{
	efi_status_t status;
	unsigned long lsize = 4;
	unsigned long tmpdb[4];
	void *db = NULL;

	status = efi.get_variable(name, guid, NULL, &lsize, &tmpdb);
	if (status != EFI_BUFFER_TOO_SMALL) {
		pr_err("Couldn't get size: 0x%lx\n", status);
		return NULL;
	}

	db = kmalloc(lsize, GFP_KERNEL);
	if (!db) {
		pr_err("Couldn't allocate memory for uefi cert list\n");
		goto out;
	}

	status = efi.get_variable(name, guid, NULL, &lsize, db);
	if (status != EFI_SUCCESS) {
		kfree(db);
		db = NULL;
		pr_err("Error reading db var: 0x%lx\n", status);
	}
out:
	*size = lsize;
	return db;
}

/*
 *  * Load the certs contained in the UEFI databases
 *   */
static int __init load_uefi_certs(void)
{
	efi_guid_t secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	efi_guid_t mok_var = EFI_SHIM_LOCK_GUID;
	void *db = NULL, *dbx = NULL, *mok = NULL;
	unsigned long dbsize = 0, dbxsize = 0, moksize = 0;
	int ignore_db, rc = 0;

	/* Check if SB is enabled and just return if not */
	if (!efi_enabled(EFI_SECURE_BOOT))
		return 0;

	/* See if the user has setup Ignore DB mode */
	ignore_db = check_ignore_db();

	/* Get db, MokListRT, and dbx.  They might not exist, so it isn't
	 * an error if we can't get them.
	 */
	if (!ignore_db) {
		db = get_cert_list(L"db", &secure_var, &dbsize);
		if (!db) {
			pr_err("MODSIGN: Couldn't get UEFI db list\n");
		} else {
			rc = parse_efi_signature_list(db, dbsize, system_trusted_keyring);
			if (rc)
				pr_err("Couldn't parse db signatures: %d\n", rc);
			kfree(db);
		}
	}

	mok = get_cert_list(L"MokListRT", &mok_var, &moksize);
	if (!mok) {
		pr_info("MODSIGN: Couldn't get UEFI MokListRT\n");
	} else {
		rc = parse_efi_signature_list(mok, moksize, system_trusted_keyring);
		if (rc)
			pr_err("Couldn't parse MokListRT signatures: %d\n", rc);
		kfree(mok);
	}

	dbx = get_cert_list(L"dbx", &secure_var, &dbxsize);
	if (!dbx) {
		pr_info("MODSIGN: Couldn't get UEFI dbx list\n");
	} else {
		rc = parse_efi_signature_list(dbx, dbxsize,
			system_blacklist_keyring);
		if (rc)
			pr_err("Couldn't parse dbx signatures: %d\n", rc);
		kfree(dbx);
	}

	return rc;
}
late_initcall(load_uefi_certs);
