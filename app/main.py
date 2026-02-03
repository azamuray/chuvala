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
import hmac
import hashlib

# Initialize Templates
templates = Jinja2Templates(directory="app/templates")

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Chuvala SSO")

# --- Startup: Migrate new columns ---
@app.on_event("startup")
def startup_db_migrate():
    from sqlalchemy import text
    db = database.SessionLocal()
    try:
        # Add telegram_id column if not exists
        db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_id BIGINT UNIQUE"))
        db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_username VARCHAR"))
        # Make email nullable for Telegram-only users
        db.execute(text("ALTER TABLE users ALTER COLUMN email DROP NOT NULL"))
        db.execute(text("ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL"))
        db.commit()
        print("Migration: Telegram columns added")
    except Exception as e:
        print(f"Migration warning: {e}")
        db.rollback()
    finally:
        db.close()

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
    allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:80,http://localhost,http://127.0.0.1,https://devosh.ru,https://trollai.ru,https://ingals.ru,https://damdac.ru,https://chuvala.ru").split(",")
    # Clean up whitespace
    allowed_origins = [origin.strip() for origin in allowed_origins]

    if not url:
        return default

    # Allow relative URLs (same host)
    if url.startswith("/"):
        return url

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

# --- Telegram Auth ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

def verify_telegram_auth(data: dict) -> bool:
    """Verify Telegram Login Widget data"""
    if not TELEGRAM_BOT_TOKEN:
        return False

    check_hash = data.pop('hash', None)
    if not check_hash:
        return False

    # Create data check string
    data_check_arr = [f"{k}={v}" for k, v in sorted(data.items())]
    data_check_string = "\n".join(data_check_arr)

    # Create secret key from bot token
    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()

    # Calculate hash
    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()

    return calculated_hash == check_hash

@app.get("/login/telegram")
async def login_telegram(request: Request, redirect_to: str = None):
    """Store redirect URL for Telegram auth"""
    if redirect_to:
        request.session['next_url'] = redirect_to
    # Redirect to login page with telegram param to trigger widget
    return RedirectResponse(url=f"/login?method=telegram&redirect_to={redirect_to or ''}")

@app.get("/auth/telegram/callback")
async def auth_telegram(request: Request, db: Session = Depends(get_db)):
    """Handle Telegram Login Widget callback"""
    # Get all query params
    params = dict(request.query_params)

    # Extract telegram data
    telegram_id = params.get('id')
    first_name = params.get('first_name', '')
    last_name = params.get('last_name', '')
    username = params.get('username', '')
    photo_url = params.get('photo_url', '')
    auth_date = params.get('auth_date', '')
    hash_value = params.get('hash', '')

    if not telegram_id or not hash_value:
        raise HTTPException(status_code=400, detail="Invalid Telegram auth data")

    # Verify hash
    verify_data = {
        'id': telegram_id,
        'first_name': first_name,
        'auth_date': auth_date,
        'hash': hash_value
    }
    if last_name:
        verify_data['last_name'] = last_name
    if username:
        verify_data['username'] = username
    if photo_url:
        verify_data['photo_url'] = photo_url

    if not verify_telegram_auth(verify_data.copy()):
        raise HTTPException(status_code=400, detail="Telegram auth verification failed")

    # Check auth_date (not older than 1 day)
    import time
    if int(auth_date) < time.time() - 86400:
        raise HTTPException(status_code=400, detail="Telegram auth expired")

    telegram_id_int = int(telegram_id)

    # Find or create user
    user = db.query(models.User).filter(models.User.telegram_id == telegram_id_int).first()

    if not user:
        # Create new user with Telegram
        display_name = f"{first_name} {last_name}".strip() or username or f"tg_{telegram_id}"
        new_user = models.User(
            email=None,  # Telegram users may not have email
            hashed_password=None,
            avatar=photo_url or None,
            telegram_id=telegram_id_int,
            telegram_username=username or None
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        user = new_user
    else:
        # Update avatar/username if changed
        if photo_url and user.avatar != photo_url:
            user.avatar = photo_url
        if username and user.telegram_username != username:
            user.telegram_username = username
        db.commit()

    # Issue JWT - use telegram_id as sub since email may be null
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    sub = user.email or f"tg:{telegram_id_int}"
    access_token = auth.create_access_token(
        data={"sub": sub, "method": "telegram", "telegram_id": telegram_id_int},
        expires_delta=access_token_expires
    )

    # Retrieve redirect destination from session
    next_url = request.session.pop('next_url', None)
    final_url = get_safe_redirect(next_url)

    if final_url:
        redirect_url = f"{final_url}?token={access_token}"
        response = RedirectResponse(url=redirect_url)
        response.set_cookie(key="chuvala_token", value=access_token, httponly=True, max_age=604800, samesite="lax")
        return response
    else:
        response = templates.TemplateResponse("dashboard.html", {
            "request": request,
            "email": user.email or f"@{username}" or f"Telegram {telegram_id}",
            "token": access_token,
            "devosh_url": os.getenv("DEVOSH_URL", "https://devosh.ru"),
            "trollai_url": os.getenv("TROLLAI_URL", "https://trollai.ru"),
            "ingals_url": os.getenv("INGALS_URL", "https://ingals.ru"),
            "damdac_url": os.getenv("DAMDAC_URL", "https://damdac.ru"),
        })
        response.set_cookie(key="chuvala_token", value=access_token, httponly=True)
        return response

# --- Account Linking (Telegram <-> Email/Google) ---
@app.get("/link", response_class=HTMLResponse)
async def link_account_page(request: Request, token: str = None):
    """Page for linking Telegram account to existing account"""
    if not token:
        return templates.TemplateResponse("link_error.html", {
            "request": request,
            "error": "Неверная ссылка. Используй /link в боте Damdac."
        })

    # Verify link token
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        telegram_id = payload.get("telegram_id")
        purpose = payload.get("purpose")

        if purpose != "link_account" or not telegram_id:
            raise Exception("Invalid token")
    except Exception as e:
        return templates.TemplateResponse("link_error.html", {
            "request": request,
            "error": "Ссылка недействительна или истекла. Запроси новую через /link в боте."
        })

    # Store token in session for after login
    request.session['link_token'] = token

    # Check if user already logged in
    existing_token = request.cookies.get("chuvala_token")
    if existing_token:
        try:
            user_payload = jwt.decode(existing_token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
            email = user_payload.get("sub")
            # Redirect to link confirmation
            return RedirectResponse(url=f"/link/confirm?token={token}")
        except:
            pass

    # Show login page with link context
    return templates.TemplateResponse("link_login.html", {
        "request": request,
        "telegram_id": telegram_id,
        "token": token
    })

@app.get("/link/confirm", response_class=HTMLResponse)
async def link_confirm_page(request: Request, token: str, db: Session = Depends(get_db)):
    """Confirm linking after user is logged in"""
    # Get current user from cookie
    user_token = request.cookies.get("chuvala_token")
    if not user_token:
        return RedirectResponse(url=f"/link?token={token}")

    try:
        user_payload = jwt.decode(user_token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email = user_payload.get("sub")
    except:
        return RedirectResponse(url=f"/link?token={token}")

    # Verify link token
    try:
        link_payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        telegram_id = link_payload.get("telegram_id")
        telegram_username = link_payload.get("telegram_username")

        if not telegram_id:
            raise Exception("No telegram_id")
    except:
        return templates.TemplateResponse("link_error.html", {
            "request": request,
            "error": "Ссылка истекла. Запроси новую через /link в боте."
        })

    # Find user by email
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse("link_error.html", {
            "request": request,
            "error": "Пользователь не найден."
        })

    # Check if telegram_id already linked to another account
    existing = db.query(models.User).filter(models.User.telegram_id == telegram_id).first()
    if existing and existing.id != user.id:
        # Delete the telegram-only account, we'll merge into the main one
        db.delete(existing)

    # Link telegram to this account
    user.telegram_id = telegram_id
    if telegram_username:
        user.telegram_username = telegram_username
    db.commit()

    # Call Damdac internal API to merge accounts there too
    import httpx
    damdac_api_url = os.getenv("DAMDAC_API_URL", "https://damdac.ru")
    internal_secret = os.getenv("INTERNAL_API_SECRET", "damdac_internal_secret_key")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{damdac_api_url}/api/internal/link-account",
                json={
                    "email": email,
                    "telegram_id": telegram_id,
                    "secret": internal_secret
                },
                timeout=10.0
            )
            print(f"Damdac link response: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Failed to notify Damdac about link: {e}")
        # Don't fail the flow, linking in Chuvala still succeeded

    return templates.TemplateResponse("link_success.html", {
        "request": request,
        "email": email,
        "telegram_username": telegram_username or telegram_id
    })

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

