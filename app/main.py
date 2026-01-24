from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from . import models, schemas, auth, database
from .database import engine
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from starlette.requests import Request
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
import os

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Chuvala SSO")

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.middleware.cors import CORSMiddleware

# Trust Proxy Headers (for HTTPS offload)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Session Middleware is required for Authlib
app.add_middleware(SessionMiddleware, secret_key=auth.SECRET_KEY)

# Social Auth Setup
config = Config(".env")
oauth = OAuth(config)

# Get keys and strip whitespace (common copy-paste error)
raw_client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
raw_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

# Debug: Print loaded config (Masked)
print(f"DEBUG: Client ID Length: {len(raw_client_id)}")
print(f"DEBUG: Client ID: {raw_client_id[:5]}...{raw_client_id[-5:]} (Check for typos!)")
print(f"DEBUG: Client Secret Length: {len(raw_client_secret)}")
if len(raw_client_secret) > 5:
    print(f"DEBUG: Client Secret: {raw_client_secret[:3]}...{raw_client_secret[-3:]}")
else:
    print("DEBUG: Client Secret seems too short!")

oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=raw_client_id,
    client_secret=raw_client_secret,
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post'
    }
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

from datetime import timedelta
from jose import JWTError, jwt

@app.get("/users/me", response_model=schemas.User)
async def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user

@app.get("/login/google")
async def login_google(request: Request):
    # Absolute URL for callback
    redirect_uri = request.url_for('auth_google')
    
    # Force HTTPS if behind proxy (common issue with Google Auth)
    if os.getenv("VIRTUAL_HOST"):
        redirect_uri = str(redirect_uri).replace("http://", "https://")
    
    print(f"DEBUG: Generated Redirect URI: {redirect_uri}") # Debug log
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        # If user cancels or error
        raise HTTPException(status_code=400, detail=f"Google Auth Failed: {str(e)}")

    user_info = token.get('userinfo')
    if not user_info:
        # Fallback if userinfo not in token (depends on scope)
        user_info = await oauth.google.userinfo(token=token)
        
    email = user_info.get('email')
    google_id = user_info.get('sub')
    picture = user_info.get('picture')

    if not email:
        raise HTTPException(status_code=400, detail="Google account has no email")

    # Find or Create User
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        # Create new user
        # We don't have a password for them, so we set a dummy hash or handle it cleanly.
        # For now, we'll just set an unusable password hash.
        new_user = models.User(
            email=email,
            hashed_password=auth.get_password_hash("SOCIAL_LOGIN_NO_PASSWORD"),
            avatar=picture,
            google_id=google_id
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        user = new_user
    else:
        # Update google_id if missing
        if not user.google_id:
            user.google_id = google_id
            if picture and not user.avatar:
                user.avatar = picture
            db.commit()

    # Issue JWT
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    # Redirect to Frontend with Token
    # In production, this should be https://devosh.ru
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:80")
    redirect_url = f"{frontend_url}?token={access_token}"
    return RedirectResponse(url=redirect_url)

