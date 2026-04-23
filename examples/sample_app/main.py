from fastapi import FastAPI
from services import (
    admin_service,
    get_invoices_data,
    get_public_info_data,
    fetch_user_data,
    submit_contact,
)

app = FastAPI()


@app.get("/users")
def get_users():
    return fetch_user_data()


@app.get("/profile")
def get_profile():
    return admin_service.delete_user()


@app.post("/contact")
def contact():
    return submit_contact()


@app.get("/public-info")
def get_public_info():
    return get_public_info_data()


@app.get("/invoices")
def get_invoices():
    return get_invoices_data()


@app.get("/health")
def health():
    return {"status": "ok"}