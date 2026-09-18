"""Authentication tests."""

from conftest import register


def test_register_login_logout_flow(logged_in_client):
    # dashboard accessible after login
    resp = logged_in_client.get("/dashboard")
    assert resp.status_code == 200

    # logout requires POST (GET is rejected)
    resp = logged_in_client.get("/logout")
    assert resp.status_code == 405

    resp = logged_in_client.post("/logout")
    assert resp.status_code == 302

    # dashboard now requires login
    resp = logged_in_client.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_register_duplicate_username(client):
    register(client)
    resp = register(client)
    assert resp.status_code == 200
    assert "already exists" in resp.get_data(as_text=True)


def test_register_accepts_any_nonempty_password(client):
    resp = client.post(
        "/register",
        data={
            "username": "weakuser",
            "display_name": "Weak User",
            "password": "1234",
            "confirm_password": "1234",
        },
    )
    # short/simple passwords are allowed now
    assert resp.status_code == 302


def test_register_empty_password_rejected(client):
    resp = client.post(
        "/register",
        data={
            "username": "nopass",
            "display_name": "No Pass",
            "password": "",
            "confirm_password": "",
        },
    )
    assert "Password cannot be empty" in resp.get_data(as_text=True)


def test_register_accepts_symbols_and_uppercase_username(client):
    resp = client.post(
        "/register",
        data={
            "username": "My.Name+Tag",
            "display_name": "Fancy User",
            "password": "x",
            "confirm_password": "x",
        },
    )
    assert resp.status_code == 302


def test_register_username_with_space_rejected(client):
    resp = client.post(
        "/register",
        data={
            "username": "bad username",
            "display_name": "Bad User",
            "password": "StrongPass1",
            "confirm_password": "StrongPass1",
        },
    )
    assert "Username must be" in resp.get_data(as_text=True)


def test_login_wrong_password(client):
    register(client)
    resp = client.post("/login", data={"username": "teacher1", "password": "wrongpass1"})
    assert "Invalid username or password" in resp.get_data(as_text=True)


def test_login_username_enumeration_is_generic(client):
    resp = client.post("/login", data={"username": "nouser", "password": "whatever1"})
    assert "Invalid username or password" in resp.get_data(as_text=True)


def test_api_requires_authentication(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 401
    assert resp.is_json
    assert "unauthorized" in resp.get_data(as_text=True)


def test_password_hash_is_never_plaintext(db, client):
    register(client)
    from app.database import users
    from sqlalchemy import select

    row = db.session.execute(select(users.c.password_hash)).scalar()
    assert row.startswith("scrypt:") or row.startswith("pbkdf2:")
    assert "StrongPass1" not in row
