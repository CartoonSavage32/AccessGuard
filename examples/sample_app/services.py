class BillingService:
    def get_data(self):
        return db.fetch()


class AdminService:
    def delete_user(self):
        return "deleted"

    def reset_system(self):
        return "reset"


class EmailService:
    def get_public_info(self):
        return decrypt_token()


class InvoiceService:
    def get_data(self):
        return db.fetch()


class DB:
    def fetch(self):
        return "secret"


class AuthDatabase:
    def read_secret(self):
        return "token-secret"


db = DB()
billing_service = BillingService()
admin_service = AdminService()
email_service = EmailService()
invoice_service = InvoiceService()
auth_database = AuthDatabase()


def fetch_user_data():
    return billing_service.get_data()


def helper():
    return admin_service.reset_system()


def submit_contact():
    return helper()


def decrypt_token():
    return auth_database.read_secret()


def get_public_info_data():
    return email_service.get_public_info()


def get_invoices_data():
    return invoice_service.get_data()
