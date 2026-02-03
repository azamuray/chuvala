from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from . import models, schemas, auth, database
from .database import engine
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from starlette.requests import Request
from starlette.responses import RedirectResponse, HTMLResponse
from starlette.templating import Jinja2Templates
from authlib.integrations.starlette_client import OAuth
import os

# Initialize Templates
templates = Jinja2Templates(directory="app/templates")

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Chuvala SSO")

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.middleware.cors import CORSMiddleware

# Trust Proxy Headers (for HTTPS offload)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Session Middleware is required for Authlib
# same_site="lax" allows cookie on redirect back from Google
# https_only=True sets Secure flag for HTTPS
is_production = os.getenv("VIRTUAL_HOST") is not None
app.add_middleware(
    SessionMiddleware,
    secret_key=auth.SECRET_KEY,
    same_site="lax",
    https_only=is_production
)

# Social Auth Setup
config = Config(".env")
oauth = OAuth(config)

# Get keys and strip whitespace (common copy-paste error)
raw_client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
raw_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

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
        data={"sub": user.email, "method": "standard"}, expires_delta=access_token_expires
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

# --- Helper: Validate Redirect URL ---
def get_safe_redirect(url: str, default: str = None) -> str:
    allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:80,http://localhost,http://127.0.0.1,https://devosh.ru,https://trollai.ru,https://ingals.ru,https://damdac.ru").split(",")
    # Clean up whitespace
    allowed_origins = [origin.strip() for origin in allowed_origins]
    
    if not url:
        return default
    
    for origin in allowed_origins:
        if url.startswith(origin):
            return url
    
    print(f"SECURITY WARNING: Invalid redirect attempt to {url}")
    return default

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, redirect_to: str = None):
    # SSO Logic: If already logged in (cookie exists), redirect immediately
    token = request.cookies.get("chuvala_token")
    if token:
        try:
            # Validate token locally
            jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
            
            # If valid, redirect back with token
            target = get_safe_redirect(redirect_to)
            if target:
                sep = "&" if "?" in target else "?"
                return RedirectResponse(url=f"{target}{sep}token={token}")
            else:
                return RedirectResponse(url="/")
        except:
            # Token invalid, proceed to login form
            pass

    if redirect_to:
        request.session['next_url'] = redirect_to
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/login/google")
async def login_google(request: Request, redirect_to: str = None):
    # Absolute URL for callback
    redirect_uri = request.url_for('auth_google')
    
    # Force HTTPS if behind proxy (common issue with Google Auth)
    if os.getenv("VIRTUAL_HOST"):
        redirect_uri = str(redirect_uri).replace("http://", "https://")
    
    # Store the intended destination in the Session (Cookie)
    if redirect_to:
        request.session['next_url'] = redirect_to
    
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/check")
async def auth_check(request: Request, redirect_to: str, fail_to: str = None):
    # SSO Logic: If already logged in (cookie exists), redirect immediately
    token = request.cookies.get("chuvala_token")
    
    if token:
        try:
            # Validate token locally
            jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
            
            # If valid, redirect back with token to APP
            target = get_safe_redirect(redirect_to)
            if target:
                sep = "&" if "?" in target else "?"
                return RedirectResponse(url=f"{target}{sep}token={token}")
        except:
            # Token invalid
            pass

    # No session or invalid session -> Go to landing page
    fallback = get_safe_redirect(fail_to, default="/login")
    return RedirectResponse(url=fallback)

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
        data={"sub": user.email, "method": "google"}, expires_delta=access_token_expires
    )
    
    # Retrieve redirect destination from session
    next_url = request.session.pop('next_url', None)
    
    # Validate destination
    final_url = get_safe_redirect(next_url)
    
    if final_url:
        redirect_url = f"{final_url}?token={access_token}"
        response = RedirectResponse(url=redirect_url)
        # CRITICAL: Set cookie so other apps can perform SSO check later
        response.set_cookie(key="chuvala_token", value=access_token, httponly=True, max_age=604800, samesite="lax")
        return response
    else:
        # Show Dashboard AND set cookie
        response = templates.TemplateResponse("dashboard.html", {
            "request": request,
            "email": user.email,
            "token": access_token,
            "devosh_url": os.getenv("DEVOSH_URL", "https://devosh.ru"),
            "trollai_url": os.getenv("TROLLAI_URL", "https://trollai.ru"),
            "ingals_url": os.getenv("INGALS_URL", "https://ingals.ru"),
            "damdac_url": os.getenv("DAMDAC_URL", "https://damdac.ru"),
        })
        response.set_cookie(key="chuvala_token", value=access_token, httponly=True)
        return response

# --- Logout Endpoint ---
@app.get("/logout")
async def logout(request: Request, redirect_uri: str = None):
    # Check current token to determine login method
    cookie_token = request.cookies.get("chuvala_token")
    login_method = "standard" # Default
    
    if cookie_token:
        try:
            # Decode without verification to get method (verification happens at check)
            # Or verify if we want to be strict. Let's just decode unverified to be fast/forgiving.
            payload = jwt.decode(cookie_token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
            login_method = payload.get("method", "standard")
        except:
            pass

    # Clear local session
    request.session.clear()
    
    # Validate and set redirect target
    target = get_safe_redirect(redirect_uri, default="/login")
    
    # Always redirect to target - Google logout breaks the flow
    # The local session is cleared, which is enough for app logout
    if True:
        # Standard logout - just redirect to login/target
        logout_url = target
    
    response = RedirectResponse(url=logout_url, status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="chuvala_token")
    
    return response

# --- New Root Endpoint for Persistent Dashboard ---
@app.get("/", response_class=HTMLResponse)
async def root_dashboard(request: Request, token: str = None, db: Session = Depends(get_db)):
    # 1. Check Query Param (e.g. from just-logged-in redirect)
    # 2. Check Cookie
    
    active_token = token or request.cookies.get("chuvala_token")
    
    if not active_token:
        return RedirectResponse(url="/login")
        
    # Validate Token
    try:
        payload = jwt.decode(active_token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
             raise Exception("Invalid token")
    except Exception:
        # Invalid token -> Redirect Login
        return RedirectResponse(url="/login")

    # Render Dashboard
    response = templates.TemplateResponse("dashboard.html", {
            "request": request,
            "email": email,
            "token": active_token,
            "devosh_url": os.getenv("DEVOSH_URL", "https://devosh.ru"),
            "trollai_url": os.getenv("TROLLAI_URL", "https://trollai.ru"),
            "ingals_url": os.getenv("INGALS_URL", "https://ingals.ru"),
            "damdac_url": os.getenv("DAMDAC_URL", "https://damdac.ru"),
        })
    
    # If token came from URL, set cookie for future
    if token:
        response.set_cookie(key="chuvala_token", value=token, httponly=True, max_age=604800, samesite="lax")
    elif active_token:
        # Sliding Session: Refresh cookie expiration
        response.set_cookie(key="chuvala_token", value=active_token, httponly=True, max_age=604800, samesite="lax")
        
    return response

