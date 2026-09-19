from passlib.context import CryptContext
from flask_jwt_extended import get_jwt_identity

from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def current_user(db) -> "User | None":
    """Resolve the authenticated user from the JWT.

    The token subject is always the user's numeric ID (see the login route), so
    every protected endpoint must look the user up by ID — never by username —
    to guarantee that the login response, /me and write endpoints all resolve
    the very same account. Returns None for a missing/non-numeric identity.
    """
    identity = get_jwt_identity()
    try:
        user_id = int(identity)
    except (TypeError, ValueError):
        return None
    if user_id <= 0:
        return None
    return db.get(User, user_id)
