from passlib.context import CryptContext
from flask_jwt_extended import get_jwt_identity

from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def current_user(db) -> User | None:
    """Resolve the JWT subject to a user.

    Access tokens are always issued with the user's integer id as the
    subject (see ``create_access_token(identity=str(user.id))``), so every
    protected endpoint must resolve the identity by primary key. Resolving
    it as a username would either 401 or match the wrong account.
    """
    identity = get_jwt_identity()
    try:
        return db.get(User, int(identity))
    except (TypeError, ValueError):
        return None
