import os
import uuid
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional, Literal

import jwt
import pymysql
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header, status, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================

app = FastAPI(
    title="E-Commerce API",
    version="1.0.0"
)

password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)


@app.middleware("http")
async def standard_api_success_envelope(request: Request, call_next):
    """Apply the FRD success response format to versioned API endpoints."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/v1/") or response.status_code >= 400:
        return response
    content_type = response.headers.get("content-type", "")
    if "application/json" not in content_type:
        return response
    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        payload = json.loads(body.decode("utf-8")) if body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return response
    if isinstance(payload, dict) and payload.get("success") is True:
        return JSONResponse(payload, status_code=response.status_code, headers=dict(response.headers))
    message = "Request completed successfully"
    data = payload
    if isinstance(payload, dict) and "message" in payload:
        message = str(payload.get("message") or message)
        data = {key: value for key, value in payload.items() if key != "message"}
    return JSONResponse(
        {"success": True, "data": data, "message": message},
        status_code=response.status_code,
        headers={key: value for key, value in response.headers.items() if key.lower() not in {"content-length", "content-type"}},
    )


@app.exception_handler(HTTPException)
async def frd_http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/v1/"):
        codes = {
            400: "VALIDATION_ERROR", 401: "UNAUTHORIZED", 403: "FORBIDDEN",
            404: "NOT_FOUND", 409: "CONFLICT", 422: "VALIDATION_ERROR",
        }
        return JSONResponse(
            status_code=exc.status_code,
            headers=exc.headers,
            content={"success": False, "error": {
                "code": codes.get(exc.status_code, "REQUEST_ERROR"),
                "message": str(exc.detail),
            }},
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def frd_validation_exception_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/api/v1/"):
        return JSONResponse(
            status_code=422,
            content={"success": False, "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": exc.errors(),
            }},
        )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "30"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
WEBHOOK_SECRET = os.getenv("PAYMENT_WEBHOOK_SECRET", "")
TAX_RATE = Decimal(os.getenv("TAX_RATE", "0.00"))
SHIPPING_FEE = Decimal(os.getenv("SHIPPING_FEE", "0.00"))
if TAX_RATE < 0 or TAX_RATE > 1:
    raise RuntimeError("TAX_RATE must be between 0 and 1 (for example 0.18 for 18%).")
if SHIPPING_FEE < 0:
    raise RuntimeError("SHIPPING_FEE cannot be negative.")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing. Add it to your .env file.")


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "ecommerce_db"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        charset="utf8mb4",
    )


def fetch_one(cursor, query, params=()):
    cursor.execute(query, params)
    return cursor.fetchone()


def fetch_all(cursor, query, params=()):
    cursor.execute(query, params)
    return cursor.fetchall()


# ============================================================
# AUTHENTICATION AND ROLE PERMISSIONS
# ============================================================

def create_token(user_id: int, role: str, token_type: str, expires_delta):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_token_pair(user_id: int, role: str):
    return {
        "access_token": create_token(
            user_id, role, "access", timedelta(minutes=ACCESS_TOKEN_MINUTES)
        ),
        "refresh_token": create_token(
            user_id, role, "refresh", timedelta(days=REFRESH_TOKEN_DAYS)
        ),
        "token_type": "bearer",
    }


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Access token required")
        user_id = int(payload["sub"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            user = fetch_one(
                cursor,
                """
                SELECT u.id, u.name, u.email, u.phone, u.status, r.name AS role
                FROM users u
                JOIN roles r ON r.id = u.role_id
                WHERE u.id = %s
                """,
                (user_id,),
            )
        if not user or user["status"] != "active":
            raise HTTPException(status_code=401, detail="User is unavailable")
        return user
    finally:
        conn.close()


def require_customer(current_user=Depends(get_current_user)):
    if current_user["role"] != "customer":
        raise HTTPException(status_code=403, detail="Customer permission required")
    return current_user


def require_admin(current_user=Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin permission required")
    return current_user


def require_operations(current_user=Depends(get_current_user)):
    if current_user["role"] not in ("admin", "operations", "support"):
        raise HTTPException(status_code=403, detail="Operations permission required")
    return current_user


def add_notification(cursor, user_id: int, notification_type: str, title: str, message: str):
    cursor.execute(
        """
        INSERT INTO notifications (user_id, type, title, message)
        VALUES (%s, %s, %s, %s)
        """,
        (user_id, notification_type, title, message),
    )


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    phone: Optional[str] = Field(default=None, max_length=20)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ProductCreate(BaseModel):
    category_id: int
    name: str = Field(min_length=1, max_length=200)
    sku: str = Field(min_length=1, max_length=100)
    description: Optional[str] = None
    base_price: Decimal = Field(gt=0)
    status: Literal["active", "inactive", "draft"] = "active"
    variant_sku: Optional[str] = Field(default=None, max_length=100)
    variant_price: Optional[Decimal] = Field(default=None, gt=0)
    stock_qty: int = Field(default=0, ge=0)
    attributes: Optional[dict] = None


class ProductUpdate(BaseModel):
    category_id: Optional[int] = None
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    sku: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = None
    base_price: Optional[Decimal] = Field(default=None, gt=0)
    status: Optional[Literal["active", "inactive", "draft"]] = None


class CartItemCreate(BaseModel):
    variant_id: int
    quantity: int = Field(gt=0)


class CartItemUpdate(BaseModel):
    quantity: int = Field(gt=0)


class OrderCreate(BaseModel):
    address_id: int
    coupon_code: Optional[str] = Field(default=None, min_length=2, max_length=100)


class CouponCreate(BaseModel):
    code: str = Field(min_length=2, max_length=100)
    type: Literal["percentage", "fixed"]
    value: Decimal = Field(gt=0)
    start_date: datetime
    end_date: datetime
    usage_limit: Optional[int] = Field(default=None, ge=1)


class PaymentCreate(BaseModel):
    order_id: int
    provider: str = Field(min_length=1, max_length=100)


class PaymentWebhook(BaseModel):
    event_id: str = Field(min_length=1, max_length=255)
    transaction_ref: str = Field(min_length=1, max_length=255)
    status: Literal["success", "failed", "refunded"]
    amount: Decimal = Field(gt=0)


class ReturnRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class ReviewCreate(BaseModel):
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = Field(default=None, max_length=2000)
    order_item_id: int = Field(gt=0)


class InventoryAdjust(BaseModel):
    variant_id: int
    type: Literal["addition", "removal", "correction"]
    quantity: int = Field(gt=0)
    reference_id: Optional[int] = None



class AddressCreate(BaseModel):
    type: Literal["home", "work", "other"] = "home"
    full_name: str = Field(min_length=2, max_length=150)
    phone: str = Field(min_length=7, max_length=20)
    address_line1: str = Field(min_length=3, max_length=255)
    address_line2: Optional[str] = Field(default=None, max_length=255)
    city: str = Field(min_length=2, max_length=100)
    state: str = Field(min_length=2, max_length=100)
    postal_code: str = Field(min_length=3, max_length=20)
    country: str = Field(min_length=2, max_length=100)


class AddressUpdate(BaseModel):
    type: Optional[Literal["home", "work", "other"]] = None
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=150)
    phone: Optional[str] = Field(default=None, min_length=7, max_length=20)
    address_line1: Optional[str] = Field(default=None, min_length=3, max_length=255)
    address_line2: Optional[str] = Field(default=None, max_length=255)
    city: Optional[str] = Field(default=None, min_length=2, max_length=100)
    state: Optional[str] = Field(default=None, min_length=2, max_length=100)
    postal_code: Optional[str] = Field(default=None, min_length=3, max_length=20)
    country: Optional[str] = Field(default=None, min_length=2, max_length=100)


class WishlistItemCreate(BaseModel):
    product_id: int = Field(gt=0)


class CategoryCreate(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    slug: str = Field(min_length=2, max_length=180)
    parent_id: Optional[int] = None
    status: Literal["active", "inactive"] = "active"


class CategoryUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=150)
    slug: Optional[str] = Field(default=None, min_length=2, max_length=180)
    parent_id: Optional[int] = None
    status: Optional[Literal["active", "inactive"]] = None


class ShipmentCreate(BaseModel):
    carrier: str = Field(min_length=2, max_length=150)
    tracking_no: str = Field(min_length=3, max_length=150)


class OrderStatusUpdate(BaseModel):
    status: Literal["processing", "packed", "shipped", "out_for_delivery", "delivered", "returned"]
    note: Optional[str] = Field(default=None, max_length=500)


class UserStatusUpdate(BaseModel):
    status: Literal["active", "inactive", "blocked"]


class ReviewModeration(BaseModel):
    status: Literal["approved", "rejected"]


# ============================================================
# GENERAL
# ============================================================

@app.get("/")
def home():
    return {"message": "Welcome to the E-Commerce API", "docs": "/docs"}


@app.get("/health")
def health():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
        return {"status": "healthy", "database": "connected"}
    finally:
        conn.close()


# ============================================================
# 1. POST /api/v1/auth/register - PUBLIC
# ============================================================

@app.post("/api/v1/auth/register", status_code=201, tags=["Authentication"])
def register_user(data: RegisterRequest):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            customer_role = fetch_one(
                cursor, "SELECT id FROM roles WHERE name = 'customer'"
            )
            if not customer_role:
                raise HTTPException(500, "Customer role is missing from roles table")

            existing = fetch_one(
                cursor,
                "SELECT id FROM users WHERE email = %s OR (phone = %s AND %s IS NOT NULL)",
                (data.email, data.phone, data.phone),
            )
            if existing:
                raise HTTPException(409, "Email or phone is already registered")

            cursor.execute(
                """
                INSERT INTO users (role_id, name, email, phone, password_hash)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    customer_role["id"],
                    data.name,
                    data.email,
                    data.phone,
                    password_hash.hash(data.password),
                ),
            )
            user_id = cursor.lastrowid
            cursor.execute("INSERT INTO carts (user_id) VALUES (%s)", (user_id,))
            cursor.execute("INSERT INTO wishlists (user_id) VALUES (%s)", (user_id,))
        conn.commit()
        return {"message": "Account created successfully", "user_id": user_id}
    except HTTPException:
        conn.rollback()
        raise
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Email or phone already exists") from exc
    finally:
        conn.close()


# ============================================================
# 2. POST /api/v1/auth/login - PUBLIC
# ============================================================

@app.post("/api/v1/auth/login", tags=["Authentication"])
def login_user(data: LoginRequest):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            user = fetch_one(
                cursor,
                """
                SELECT u.id, u.name, u.email, u.password_hash, u.status,
                       r.name AS role
                FROM users u
                JOIN roles r ON r.id = u.role_id
                WHERE u.email = %s
                """,
                (data.email,),
            )
        if (
            not user
            or user["status"] != "active"
            or not password_hash.verify(data.password, user["password_hash"])
        ):
            raise HTTPException(401, "Invalid email or password")

        tokens = create_token_pair(user["id"], user["role"])
        return {
            "message": "Login successful",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
            },
            **tokens,
        }
    finally:
        conn.close()


# ============================================================
# 3. POST /api/v1/auth/refresh - CUSTOMER / ADMIN
# ============================================================

@app.post("/api/v1/auth/refresh", tags=["Authentication"])
def refresh_access_token(data: RefreshRequest):
    try:
        payload = jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Refresh token required")
        user_id = int(payload["sub"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired refresh token")

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            user = fetch_one(
                cursor,
                """
                SELECT u.id, u.status, r.name AS role
                FROM users u JOIN roles r ON r.id = u.role_id
                WHERE u.id = %s
                """,
                (user_id,),
            )
        if not user or user["status"] != "active":
            raise HTTPException(401, "User is unavailable")
        if user["role"] not in ("customer", "admin"):
            raise HTTPException(403, "Role is not permitted")
        return create_token_pair(user["id"], user["role"])
    finally:
        conn.close()


# ============================================================
# 4. GET /api/v1/categories - PUBLIC
# ============================================================

@app.get("/api/v1/categories", tags=["Categories"])
def list_categories():
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            return fetch_all(
                cursor,
                """
                SELECT id, parent_id, name, slug, status, created_at
                FROM categories
                WHERE status = 'active'
                ORDER BY name
                """,
            )
    finally:
        conn.close()


# ============================================================
# 5. GET /api/v1/products - PUBLIC (SEARCH / FILTER)
# ============================================================

@app.get("/api/v1/products", tags=["Products"])
def list_products(
    search: Optional[str] = None,
    category_id: Optional[int] = None,
    min_price: Optional[Decimal] = None,
    max_price: Optional[Decimal] = None,
    page: int = 1,
    page_size: int = 20,
    sort_by: Literal["newest", "price_asc", "price_desc", "name"] = "newest",
):
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(400, "Invalid pagination values")
    if min_price is not None and min_price < 0:
        raise HTTPException(400, "min_price cannot be negative")
    if max_price is not None and max_price < 0:
        raise HTTPException(400, "max_price cannot be negative")
    if min_price is not None and max_price is not None and min_price > max_price:
        raise HTTPException(400, "min_price cannot exceed max_price")

    conditions = ["p.status = 'active'", "c.status = 'active'"]
    params = []
    if search:
        conditions.append("(p.name LIKE %s OR p.description LIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])
    if category_id is not None:
        conditions.append("p.category_id = %s")
        params.append(category_id)
    if min_price is not None:
        conditions.append("p.base_price >= %s")
        params.append(min_price)
    if max_price is not None:
        conditions.append("p.base_price <= %s")
        params.append(max_price)

    where_clause = " AND ".join(conditions)
    sort_sql = {
        "newest": "p.created_at DESC, p.id DESC",
        "price_asc": "p.base_price ASC, p.id ASC",
        "price_desc": "p.base_price DESC, p.id DESC",
        "name": "p.name ASC, p.id ASC",
    }[sort_by]
    offset = (page - 1) * page_size
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            products = fetch_all(
                cursor,
                f"""
                SELECT p.id, p.category_id, c.name AS category_name,
                       p.name, p.sku, p.description, p.base_price, p.status,
                       p.created_at,
                       COALESCE(SUM(pv.stock_qty), 0) AS total_stock
                FROM products p
                JOIN categories c ON c.id = p.category_id
                LEFT JOIN product_variants pv ON pv.product_id = p.id
                WHERE {where_clause}
                GROUP BY p.id
                ORDER BY {sort_sql}
                LIMIT %s OFFSET %s
                """,
                tuple(params + [page_size, offset]),
            )
            count_row = fetch_one(
                cursor,
                f"""
                SELECT COUNT(*) AS total
                FROM products p JOIN categories c ON c.id = p.category_id
                WHERE {where_clause}
                """,
                tuple(params),
            )
        return {
            "page": page,
            "page_size": page_size,
            "total": count_row["total"],
            "products": products,
        }
    finally:
        conn.close()


# ============================================================
# 6. GET /api/v1/products/{id} - PUBLIC
# ============================================================

@app.get("/api/v1/products/{product_id}", tags=["Products"])
def get_product(product_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            product = fetch_one(
                cursor,
                """
                SELECT p.id, p.category_id, c.name AS category_name,
                       p.name, p.sku, p.description, p.base_price,
                       p.status, p.created_at
                FROM products p
                JOIN categories c ON c.id = p.category_id
                WHERE p.id = %s AND p.status = 'active'
                """,
                (product_id,),
            )
            if not product:
                raise HTTPException(404, "Product not found")

            product["variants"] = fetch_all(
                cursor,
                """
                SELECT id, sku, attributes, price, stock_qty
                FROM product_variants
                WHERE product_id = %s
                """,
                (product_id,),
            )
            product["images"] = fetch_all(
                cursor,
                """
                SELECT id, image_url, sort_order
                FROM product_images
                WHERE product_id = %s
                ORDER BY sort_order
                """,
                (product_id,),
            )
            product["reviews"] = fetch_all(
                cursor,
                """
                SELECT r.id, r.rating, r.comment, r.created_at, u.name AS customer_name
                FROM reviews r
                JOIN users u ON u.id = r.user_id
                WHERE r.product_id = %s AND r.status = 'approved'
                ORDER BY r.created_at DESC
                """,
                (product_id,),
            )
            rating = fetch_one(
                cursor,
                """
                SELECT COUNT(*) AS review_count, COALESCE(AVG(rating), 0) AS average_rating
                FROM reviews
                WHERE product_id = %s AND status = 'approved'
                """,
                (product_id,),
            )
            product["review_summary"] = rating
        return product
    finally:
        conn.close()


# ============================================================
# CART HELPERS
# ============================================================

def get_or_create_active_cart(cursor, user_id: int):
    cart = fetch_one(
        cursor,
        "SELECT id FROM carts WHERE user_id = %s AND status = 'active' ORDER BY id DESC LIMIT 1",
        (user_id,),
    )
    if cart:
        return cart["id"]
    cursor.execute("INSERT INTO carts (user_id) VALUES (%s)", (user_id,))
    return cursor.lastrowid


# ============================================================
# 7. GET /api/v1/cart - CUSTOMER
# ============================================================

@app.get("/api/v1/cart", tags=["Cart"])
def view_cart(current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cart_id = get_or_create_active_cart(cursor, current_user["id"])
            items = fetch_all(
                cursor,
                """
                SELECT ci.id, ci.variant_id, ci.quantity, pv.price AS unit_price,
                       (ci.quantity * pv.price) AS line_total,
                       pv.stock_qty, pv.sku AS variant_sku, pv.attributes,
                       p.id AS product_id, p.name AS product_name
                FROM cart_items ci
                JOIN product_variants pv ON pv.id = ci.variant_id
                JOIN products p ON p.id = pv.product_id
                WHERE ci.cart_id = %s
                ORDER BY ci.id
                """,
                (cart_id,),
            )
        conn.commit()
        subtotal = sum(
            (Decimal(str(item["line_total"])) for item in items), Decimal("0")
        )
        return {
            "cart_id": cart_id,
            "items": items,
            "subtotal": subtotal,
        }
    finally:
        conn.close()


# ============================================================
# 8. POST /api/v1/cart/items - CUSTOMER
# ============================================================

@app.post("/api/v1/cart/items", status_code=201, tags=["Cart"])
def add_cart_item(data: CartItemCreate, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cart_id = get_or_create_active_cart(cursor, current_user["id"])
            variant = fetch_one(
                cursor,
                """
                SELECT pv.id, pv.price, pv.stock_qty, p.status
                FROM product_variants pv
                JOIN products p ON p.id = pv.product_id
                WHERE pv.id = %s
                """,
                (data.variant_id,),
            )
            if not variant or variant["status"] != "active":
                raise HTTPException(404, "Product variant not found")
            if data.quantity > variant["stock_qty"]:
                raise HTTPException(400, "Requested quantity exceeds available stock")

            existing = fetch_one(
                cursor,
                "SELECT id, quantity FROM cart_items WHERE cart_id = %s AND variant_id = %s",
                (cart_id, data.variant_id),
            )
            if existing:
                new_quantity = existing["quantity"] + data.quantity
                if new_quantity > variant["stock_qty"]:
                    raise HTTPException(400, "Requested quantity exceeds available stock")
                cursor.execute(
                    """
                    UPDATE cart_items SET quantity = %s, unit_price = %s
                    WHERE id = %s
                    """,
                    (new_quantity, variant["price"], existing["id"]),
                )
                item_id = existing["id"]
            else:
                cursor.execute(
                    """
                    INSERT INTO cart_items (cart_id, variant_id, quantity, unit_price)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (cart_id, data.variant_id, data.quantity, variant["price"]),
                )
                item_id = cursor.lastrowid
        conn.commit()
        return {"message": "Item added to cart", "cart_item_id": item_id}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 9. PATCH /api/v1/cart/items/{id} - CUSTOMER
# ============================================================

@app.patch("/api/v1/cart/items/{item_id}", tags=["Cart"])
def update_cart_item(
    item_id: int,
    data: CartItemUpdate,
    current_user=Depends(require_customer),
):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            item = fetch_one(
                cursor,
                """
                SELECT ci.id, ci.variant_id, ci.cart_id
                FROM cart_items ci
                JOIN carts c ON c.id = ci.cart_id
                WHERE ci.id = %s AND c.user_id = %s AND c.status = 'active'
                """,
                (item_id, current_user["id"]),
            )
            if not item:
                raise HTTPException(404, "Cart item not found")

            variant = fetch_one(
                cursor,
                "SELECT price, stock_qty FROM product_variants WHERE id = %s",
                (item["variant_id"],),
            )
            if data.quantity > variant["stock_qty"]:
                raise HTTPException(400, "Requested quantity exceeds available stock")

            cursor.execute(
                "UPDATE cart_items SET quantity = %s, unit_price = %s WHERE id = %s",
                (data.quantity, variant["price"], item_id),
            )
        conn.commit()
        return {"message": "Cart quantity updated"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 10. DELETE /api/v1/cart/items/{id} - CUSTOMER
# ============================================================

@app.delete("/api/v1/cart/items/{item_id}", tags=["Cart"])
def remove_cart_item(item_id: int, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                DELETE ci FROM cart_items ci
                JOIN carts c ON c.id = ci.cart_id
                WHERE ci.id = %s AND c.user_id = %s AND c.status = 'active'
                """,
                (item_id, current_user["id"]),
            )
            if cursor.rowcount == 0:
                raise HTTPException(404, "Cart item not found")
        conn.commit()
        return {"message": "Cart item removed"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 11. POST /api/v1/orders - CUSTOMER
# ============================================================

@app.post("/api/v1/orders", status_code=201, tags=["Orders"])
def create_order(data: OrderCreate, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            address = fetch_one(
                cursor,
                "SELECT id FROM addresses WHERE id = %s AND user_id = %s",
                (data.address_id, current_user["id"]),
            )
            if not address:
                raise HTTPException(404, "Delivery address not found")

            cart = fetch_one(
                cursor,
                "SELECT id FROM carts WHERE user_id = %s AND status = 'active' ORDER BY id DESC LIMIT 1",
                (current_user["id"],),
            )
            if not cart:
                raise HTTPException(400, "Cart is empty")

            cart_items = fetch_all(
                cursor,
                """
                SELECT ci.variant_id, ci.quantity, pv.price, pv.stock_qty
                FROM cart_items ci
                JOIN product_variants pv ON pv.id = ci.variant_id
                WHERE ci.cart_id = %s
                FOR UPDATE
                """,
                (cart["id"],),
            )
            if not cart_items:
                raise HTTPException(400, "Cart is empty")

            subtotal = Decimal("0")
            for item in cart_items:
                if item["quantity"] > item["stock_qty"]:
                    raise HTTPException(400, "Insufficient stock for one or more items")
                subtotal += Decimal(str(item["price"])) * item["quantity"]

            discount = Decimal("0.00")
            coupon = None
            if data.coupon_code:
                coupon = fetch_one(
                    cursor,
                    """
                    SELECT id, code, type, value, usage_limit, used_count
                    FROM coupons
                    WHERE code = %s AND status = 'active'
                      AND start_date <= NOW() AND end_date >= NOW()
                    FOR UPDATE
                    """,
                    (data.coupon_code.strip().upper(),),
                )
                if not coupon:
                    raise HTTPException(400, "Coupon is invalid, inactive, or expired")
                if coupon["usage_limit"] is not None and coupon["used_count"] >= coupon["usage_limit"]:
                    raise HTTPException(400, "Coupon usage limit has been reached")
                if coupon["type"] == "percentage":
                    if Decimal(str(coupon["value"])) > Decimal("100"):
                        raise HTTPException(400, "Percentage coupon cannot exceed 100 percent")
                    discount = (subtotal * Decimal(str(coupon["value"])) / Decimal("100")).quantize(Decimal("0.01"))
                else:
                    discount = Decimal(str(coupon["value"])).quantize(Decimal("0.01"))
                discount = min(discount, subtotal)

            taxable_amount = max(subtotal - discount, Decimal("0.00"))
            tax = (taxable_amount * TAX_RATE).quantize(Decimal("0.01"))
            shipping_fee = SHIPPING_FEE if taxable_amount > 0 else Decimal("0.00")
            total = taxable_amount + tax + shipping_fee

            cursor.execute(
                """
                INSERT INTO orders
                (user_id, address_id, subtotal, discount, tax, shipping_fee, total)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    current_user["id"], data.address_id, subtotal,
                    discount, tax, shipping_fee, total,
                ),
            )
            order_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO order_status_history (order_id, old_status, new_status, note)
                VALUES (%s, NULL, 'pending', %s)
                """,
                (order_id, "Order created; awaiting payment"),
            )

            if coupon:
                cursor.execute(
                    "UPDATE coupons SET used_count = used_count + 1 WHERE id = %s",
                    (coupon["id"],),
                )
                cursor.execute(
                    """
                    INSERT INTO coupon_redemptions
                    (coupon_id, user_id, order_id, discount_amount)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (coupon["id"], current_user["id"], order_id, discount),
                )

            for item in cart_items:
                line_total = Decimal(str(item["price"])) * item["quantity"]
                cursor.execute(
                    """
                    INSERT INTO order_items
                    (order_id, variant_id, quantity, unit_price, discount, tax, total)
                    VALUES (%s, %s, %s, %s, 0, 0, %s)
                    """,
                    (
                        order_id, item["variant_id"], item["quantity"],
                        item["price"], line_total,
                    ),
                )
                cursor.execute(
                    """
                    UPDATE product_variants
                    SET stock_qty = stock_qty - %s
                    WHERE id = %s AND stock_qty >= %s
                    """,
                    (item["quantity"], item["variant_id"], item["quantity"]),
                )
                if cursor.rowcount != 1:
                    raise HTTPException(409, "Stock changed; please retry the order")

                cursor.execute(
                    """
                    INSERT INTO inventory_transactions
                    (variant_id, type, quantity, reference_id)
                    VALUES (%s, 'order', %s, %s)
                    """,
                    (item["variant_id"], -item["quantity"], order_id),
                )

            cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart["id"],))
            cursor.execute("UPDATE carts SET status = 'ordered' WHERE id = %s", (cart["id"],))
            add_notification(
                cursor, current_user["id"], "order",
                "Order placed", f"Your order #{order_id} has been created."
            )
        conn.commit()
        return {
            "message": "Order created successfully",
            "order_id": order_id,
            "subtotal": subtotal,
            "tax": tax,
            "shipping_fee": shipping_fee,
            "discount": discount,
            "total": total,
        }
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 12. GET /api/v1/orders - CUSTOMER (ORDER HISTORY)
# ============================================================

@app.get("/api/v1/orders", tags=["Orders"])
def order_history(current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            return fetch_all(
                cursor,
                """
                SELECT id, status, subtotal, discount, tax, shipping_fee,
                       total, created_at
                FROM orders
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (current_user["id"],),
            )
    finally:
        conn.close()


# ============================================================
# 13. GET /api/v1/orders/{id} - CUSTOMER
# ============================================================

@app.get("/api/v1/orders/{order_id}", tags=["Orders"])
def order_details(order_id: int, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(
                cursor,
                """
                SELECT o.*, a.full_name AS delivery_name, a.phone AS delivery_phone,
                       a.address_line1, a.address_line2, a.city, a.state,
                       a.postal_code, a.country
                FROM orders o
                JOIN addresses a ON a.id = o.address_id
                WHERE o.id = %s AND o.user_id = %s
                """,
                (order_id, current_user["id"]),
            )
            if not order:
                raise HTTPException(404, "Order not found")

            order["items"] = fetch_all(
                cursor,
                """
                SELECT oi.id, oi.variant_id, oi.quantity, oi.unit_price,
                       oi.discount, oi.tax, oi.total, pv.sku,
                       p.name AS product_name
                FROM order_items oi
                JOIN product_variants pv ON pv.id = oi.variant_id
                JOIN products p ON p.id = pv.product_id
                WHERE oi.order_id = %s
                """,
                (order_id,),
            )
            order["payments"] = fetch_all(
                cursor,
                """
                SELECT id, provider, transaction_ref, amount, status, created_at
                FROM payments WHERE order_id = %s
                """,
                (order_id,),
            )
            order["shipments"] = fetch_all(
                cursor,
                """
                SELECT id, carrier, tracking_no, status, created_at
                FROM shipments WHERE order_id = %s
                """,
                (order_id,),
            )
        return order
    finally:
        conn.close()


# ============================================================
# 14. POST /api/v1/payments - CUSTOMER
# ============================================================

@app.post("/api/v1/payments", status_code=201, tags=["Payments"])
def initiate_payment(data: PaymentCreate, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(
                cursor,
                """
                SELECT id, total, status FROM orders
                WHERE id = %s AND user_id = %s
                """,
                (data.order_id, current_user["id"]),
            )
            if not order:
                raise HTTPException(404, "Order not found")
            if order["status"] != "pending":
                raise HTTPException(400, "Payment can only be initiated for a pending order")

            pending_payment = fetch_one(
                cursor,
                "SELECT id, transaction_ref, amount FROM payments WHERE order_id = %s AND status = 'pending' ORDER BY id DESC LIMIT 1",
                (data.order_id,),
            )
            if pending_payment:
                return {
                    "message": "A payment is already pending for this order",
                    "payment_id": pending_payment["id"],
                    "transaction_ref": pending_payment["transaction_ref"],
                    "amount": pending_payment["amount"],
                    "status": "pending",
                }

            transaction_ref = f"PAY-{uuid.uuid4().hex}"
            cursor.execute(
                """
                INSERT INTO payments (order_id, provider, transaction_ref, amount)
                VALUES (%s, %s, %s, %s)
                """,
                (data.order_id, data.provider, transaction_ref, order["total"]),
            )
            payment_id = cursor.lastrowid
        conn.commit()
        return {
            "message": "Payment initiated",
            "payment_id": payment_id,
            "transaction_ref": transaction_ref,
            "amount": order["total"],
            "status": "pending",
            "note": "Connect a real payment provider to collect payment details.",
        }
    finally:
        conn.close()


# ============================================================
# 15. POST /api/v1/payments/webhook - PAYMENT GATEWAY
# ============================================================

@app.post("/api/v1/payments/webhook", tags=["Payments"])
def payment_webhook(
    data: PaymentWebhook,
    x_webhook_secret: Optional[str] = Header(default=None),
):
    """
    Shared-secret webhook endpoint.
    Production payment providers should additionally verify their native
    HMAC/signature against the raw request body before accepting an event.
    """
    if not WEBHOOK_SECRET:
        raise HTTPException(503, "Payment webhook secret is not configured")
    if x_webhook_secret != WEBHOOK_SECRET:
        raise HTTPException(401, "Invalid payment gateway credentials")

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            payment = fetch_one(
                cursor,
                """
                SELECT p.id, p.order_id, p.provider, p.status, p.amount,
                       o.user_id, o.status AS order_status
                FROM payments p
                JOIN orders o ON o.id = p.order_id
                WHERE p.transaction_ref = %s
                FOR UPDATE
                """,
                (data.transaction_ref,),
            )
            if not payment:
                raise HTTPException(404, "Payment transaction not found")
            if Decimal(str(payment["amount"])).quantize(Decimal("0.01")) != data.amount.quantize(Decimal("0.01")):
                raise HTTPException(400, "Webhook amount does not match the payment amount")

            # A unique provider/event_id pair prevents duplicate event handling.
            cursor.execute(
                """
                INSERT INTO payment_webhook_events
                    (provider, event_id, transaction_ref, event_status)
                VALUES (%s, %s, %s, %s)
                """,
                (payment["provider"], data.event_id, data.transaction_ref, data.status),
            )

            current_payment_status = payment["status"]
            if current_payment_status == data.status:
                conn.commit()
                return {"message": "Payment event already processed", "status": data.status}

            if current_payment_status == "refunded":
                raise HTTPException(409, "A refunded payment cannot be changed by a later event")
            if current_payment_status == "success" and data.status != "refunded":
                raise HTTPException(409, "A successful payment can only receive a refund event")
            if current_payment_status == "failed" and data.status != "failed":
                raise HTTPException(409, "A failed payment cannot be changed by a later event")

            if data.status == "success":
                if payment["order_status"] != "pending":
                    raise HTTPException(409, "Order is not awaiting payment")
                cursor.execute(
                    "UPDATE payments SET status = 'success' WHERE id = %s",
                    (payment["id"],),
                )
                cursor.execute(
                    "UPDATE orders SET status = 'confirmed' WHERE id = %s AND status = 'pending'",
                    (payment["order_id"],),
                )
                cursor.execute(
                    """
                    INSERT INTO order_status_history
                        (order_id, old_status, new_status, note)
                    VALUES (%s, 'pending', 'confirmed', %s)
                    """,
                    (payment["order_id"], "Payment confirmed"),
                )
                add_notification(
                    cursor, payment["user_id"], "payment",
                    "Payment successful",
                    f"Payment for order #{payment['order_id']} was successful.",
                )

            elif data.status == "failed":
                cursor.execute(
                    "UPDATE payments SET status = 'failed' WHERE id = %s",
                    (payment["id"],),
                )
                # Stock was reserved/deducted at order creation. Restore it exactly
                # once when the order is still pending payment.
                if payment["order_status"] == "pending":
                    items = fetch_all(
                        cursor,
                        "SELECT variant_id, quantity FROM order_items WHERE order_id = %s",
                        (payment["order_id"],),
                    )
                    for item in items:
                        cursor.execute(
                            "UPDATE product_variants SET stock_qty = stock_qty + %s WHERE id = %s",
                            (item["quantity"], item["variant_id"]),
                        )
                        cursor.execute(
                            """
                            INSERT INTO inventory_transactions
                                (variant_id, type, quantity, reference_id)
                            VALUES (%s, 'payment_failed_release', %s, %s)
                            """,
                            (item["variant_id"], item["quantity"], payment["order_id"]),
                        )
                    redemption = fetch_one(
                        cursor,
                        "SELECT coupon_id FROM coupon_redemptions WHERE order_id = %s FOR UPDATE",
                        (payment["order_id"],),
                    )
                    if redemption:
                        cursor.execute("UPDATE coupons SET used_count = GREATEST(used_count - 1, 0) WHERE id = %s", (redemption["coupon_id"],))
                        cursor.execute("DELETE FROM coupon_redemptions WHERE order_id = %s", (payment["order_id"],))
                    cursor.execute(
                        "UPDATE orders SET status = 'cancelled' WHERE id = %s AND status = 'pending'",
                        (payment["order_id"],),
                    )
                    cursor.execute(
                        """
                        INSERT INTO order_status_history
                            (order_id, old_status, new_status, note)
                        VALUES (%s, 'pending', 'cancelled', %s)
                        """,
                        (payment["order_id"], "Payment failed; reserved stock restored"),
                    )
                add_notification(
                    cursor, payment["user_id"], "payment",
                    "Payment failed",
                    f"Payment for order #{payment['order_id']} failed.",
                )

            elif data.status == "refunded":
                if payment["order_status"] not in ("returned", "cancelled"):
                    raise HTTPException(409, "Refund is allowed only after a return is accepted or an order is cancelled")
                cursor.execute(
                    "UPDATE payments SET status = 'refunded' WHERE id = %s",
                    (payment["id"],),
                )
                old_status = payment["order_status"]
                cursor.execute(
                    "UPDATE orders SET status = 'refunded' WHERE id = %s",
                    (payment["order_id"],),
                )
                cursor.execute(
                    """
                    INSERT INTO order_status_history
                        (order_id, old_status, new_status, note)
                    VALUES (%s, %s, 'refunded', %s)
                    """,
                    (payment["order_id"], old_status, "Refund confirmed by payment provider"),
                )
                add_notification(
                    cursor, payment["user_id"], "payment",
                    "Payment refunded",
                    f"Payment for order #{payment['order_id']} was refunded.",
                )

        conn.commit()
        return {"message": "Payment event processed", "status": data.status}
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        # Duplicate provider event IDs are safe retries.
        if getattr(exc, "args", [None])[0] == 1062:
            return {"message": "Duplicate webhook event ignored"}
        raise HTTPException(409, "Webhook event conflicts with an existing record") from exc
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 16. POST /api/v1/orders/{id}/cancel - CUSTOMER
# ============================================================

@app.post("/api/v1/orders/{order_id}/cancel", tags=["Orders"])
def cancel_order(order_id: int, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(
                cursor,
                """
                SELECT id, status FROM orders
                WHERE id = %s AND user_id = %s
                FOR UPDATE
                """,
                (order_id, current_user["id"]),
            )
            if not order:
                raise HTTPException(404, "Order not found")
            if order["status"] not in ("pending", "confirmed"):
                raise HTTPException(400, "This order can no longer be cancelled")

            successful_payment = fetch_one(
                cursor,
                "SELECT id FROM payments WHERE order_id = %s AND status = 'success' LIMIT 1",
                (order_id,),
            )
            if successful_payment:
                raise HTTPException(
                    409,
                    "This order has a successful payment. A refund must be processed before cancellation.",
                )

            items = fetch_all(
                cursor,
                "SELECT variant_id, quantity FROM order_items WHERE order_id = %s",
                (order_id,),
            )
            for item in items:
                cursor.execute(
                    """
                    UPDATE product_variants
                    SET stock_qty = stock_qty + %s WHERE id = %s
                    """,
                    (item["quantity"], item["variant_id"]),
                )
                cursor.execute(
                    """
                    INSERT INTO inventory_transactions
                    (variant_id, type, quantity, reference_id)
                    VALUES (%s, 'cancellation', %s, %s)
                    """,
                    (item["variant_id"], item["quantity"], order_id),
                )

            cursor.execute(
                "UPDATE payments SET status = 'failed' WHERE order_id = %s AND status = 'pending'",
                (order_id,),
            )
            redemption = fetch_one(
                cursor,
                "SELECT coupon_id FROM coupon_redemptions WHERE order_id = %s FOR UPDATE",
                (order_id,),
            )
            if redemption:
                cursor.execute("UPDATE coupons SET used_count = GREATEST(used_count - 1, 0) WHERE id = %s", (redemption["coupon_id"],))
                cursor.execute("DELETE FROM coupon_redemptions WHERE order_id = %s", (order_id,))
            cursor.execute(
                "UPDATE orders SET status = 'cancelled' WHERE id = %s",
                (order_id,),
            )
            cursor.execute(
                """
                INSERT INTO order_status_history (order_id, old_status, new_status, changed_by_user_id, note)
                VALUES (%s, %s, 'cancelled', %s, %s)
                """,
                (order_id, order["status"], current_user["id"], "Cancelled by customer"),
            )
            add_notification(
                cursor, current_user["id"], "order",
                "Order cancelled", f"Your order #{order_id} was cancelled."
            )
        conn.commit()
        return {"message": "Order cancelled successfully"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 17. POST /api/v1/orders/{id}/return - CUSTOMER
# ============================================================

@app.post("/api/v1/orders/{order_id}/return", tags=["Orders"])
def request_return(
    order_id: int,
    data: ReturnRequest,
    current_user=Depends(require_customer),
):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(
                cursor,
                """
                SELECT id, status FROM orders
                WHERE id = %s AND user_id = %s
                """,
                (order_id, current_user["id"]),
            )
            if not order:
                raise HTTPException(404, "Order not found")
            if order["status"] != "delivered":
                raise HTTPException(400, "Only delivered orders can be returned")

            cursor.execute(
                "UPDATE orders SET status = 'return_requested' WHERE id = %s",
                (order_id,),
            )
            cursor.execute(
                """
                INSERT INTO order_status_history (order_id, old_status, new_status, changed_by_user_id, note)
                VALUES (%s, 'delivered', 'return_requested', %s, %s)
                """,
                (order_id, current_user["id"], data.reason),
            )
            add_notification(
                cursor, current_user["id"], "return",
                "Return requested",
                f"Return requested for order #{order_id}. Reason: {data.reason}",
            )
        conn.commit()
        return {"message": "Return request submitted", "order_id": order_id}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 18. POST /api/v1/products/{id}/reviews - CUSTOMER
# ============================================================

@app.post("/api/v1/products/{product_id}/reviews", status_code=201, tags=["Reviews"])
def submit_review(
    product_id: int,
    data: ReviewCreate,
    current_user=Depends(require_customer),
):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            product = fetch_one(
                cursor, "SELECT id FROM products WHERE id = %s AND status = 'active'",
                (product_id,),
            )
            if not product:
                raise HTTPException(404, "Product not found")

            purchased_item = fetch_one(
                    cursor,
                    """
                    SELECT oi.id
                    FROM order_items oi
                    JOIN orders o ON o.id = oi.order_id
                    JOIN product_variants pv ON pv.id = oi.variant_id
                    WHERE oi.id = %s AND o.user_id = %s
                      AND pv.product_id = %s AND o.status = 'delivered'
                    """,
                    (data.order_item_id, current_user["id"], product_id),
                )
            if not purchased_item:
                raise HTTPException(400, "A review requires a matching delivered purchase")

            existing = fetch_one(
                cursor,
                """
                SELECT id FROM reviews
                WHERE user_id = %s AND product_id = %s
                """,
                (current_user["id"], product_id),
            )
            if existing:
                raise HTTPException(409, "You have already reviewed this product")

            cursor.execute(
                """
                INSERT INTO reviews
                (user_id, product_id, order_item_id, rating, comment)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    current_user["id"], product_id, data.order_item_id,
                    data.rating, data.comment,
                ),
            )
            review_id = cursor.lastrowid
        conn.commit()
        return {"message": "Review submitted for moderation", "review_id": review_id}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# 19. GET /api/v1/admin/orders - ADMIN
# ============================================================

@app.get("/api/v1/admin/orders", tags=["Admin"])
def admin_list_orders(
    order_status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    current_user=Depends(require_admin),
):
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(400, "Invalid pagination values")
    offset = (page - 1) * page_size
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            if order_status:
                return fetch_all(
                    cursor,
                    """
                    SELECT o.*, u.name AS customer_name, u.email AS customer_email
                    FROM orders o JOIN users u ON u.id = o.user_id
                    WHERE o.status = %s ORDER BY o.created_at DESC LIMIT %s OFFSET %s
                    """,
                    (order_status, page_size, offset),
                )
            return fetch_all(
                cursor,
                """
                SELECT o.*, u.name AS customer_name, u.email AS customer_email
                FROM orders o JOIN users u ON u.id = o.user_id
                ORDER BY o.created_at DESC LIMIT %s OFFSET %s
                """,
                (page_size, offset),
            )
    finally:
        conn.close()


# ============================================================
# 20. POST /api/v1/admin/products - ADMIN
# ============================================================

@app.post("/api/v1/admin/products", status_code=201, tags=["Admin"])
def admin_create_product(
    data: ProductCreate,
    current_user=Depends(require_admin),
):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            category = fetch_one(
                cursor,
                "SELECT id FROM categories WHERE id = %s",
                (data.category_id,),
            )
            if not category:
                raise HTTPException(404, "Category not found")

            cursor.execute(
                """
                INSERT INTO products
                (category_id, name, sku, description, base_price, status)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    data.category_id, data.name, data.sku,
                    data.description, data.base_price, data.status,
                ),
            )
            product_id = cursor.lastrowid

            variant_sku = data.variant_sku or f"{data.sku}-DEFAULT"
            variant_price = data.variant_price or data.base_price
            cursor.execute(
                """
                INSERT INTO product_variants
                (product_id, sku, attributes, price, stock_qty)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    product_id, variant_sku,
                    json.dumps(data.attributes) if data.attributes else None,
                    variant_price, data.stock_qty,
                ),
            )
            variant_id = cursor.lastrowid

            if data.stock_qty > 0:
                cursor.execute(
                    """
                    INSERT INTO inventory_transactions
                    (variant_id, type, quantity, reference_id)
                    VALUES (%s, 'initial_stock', %s, %s)
                    """,
                    (variant_id, data.stock_qty, product_id),
                )
        conn.commit()
        return {
            "message": "Product created successfully",
            "product_id": product_id,
            "variant_id": variant_id,
        }
    except HTTPException:
        conn.rollback()
        raise
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Product SKU or variant SKU already exists") from exc
    finally:
        conn.close()


# ============================================================
# 21. PATCH /api/v1/admin/products/{id} - ADMIN
# ============================================================

@app.patch("/api/v1/admin/products/{product_id}", tags=["Admin"])
def admin_update_product(
    product_id: int,
    data: ProductUpdate,
    current_user=Depends(require_admin),
):
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(400, "No fields supplied for update")

    allowed_columns = {"category_id", "name", "sku", "description", "base_price", "status"}
    if not set(updates).issubset(allowed_columns):
        raise HTTPException(400, "Invalid update fields")

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            product = fetch_one(
                cursor, "SELECT id FROM products WHERE id = %s", (product_id,)
            )
            if not product:
                raise HTTPException(404, "Product not found")

            if "category_id" in updates:
                category = fetch_one(
                    cursor, "SELECT id FROM categories WHERE id = %s",
                    (updates["category_id"],),
                )
                if not category:
                    raise HTTPException(404, "Category not found")

            old_product = fetch_one(
                cursor,
                "SELECT base_price FROM products WHERE id = %s FOR UPDATE",
                (product_id,),
            )
            columns = ", ".join(f"`{column}` = %s" for column in updates)
            values = list(updates.values()) + [product_id]
            cursor.execute(
                f"UPDATE products SET {columns} WHERE id = %s",
                tuple(values),
            )
            # Keep default-priced variants synchronized with the product base price.
            # Variants with custom prices remain unchanged.
            if "base_price" in updates:
                cursor.execute(
                    "UPDATE product_variants SET price = %s WHERE product_id = %s AND price = %s",
                    (updates["base_price"], product_id, old_product["base_price"]),
                )
        conn.commit()
        return {"message": "Product updated successfully"}
    except HTTPException:
        conn.rollback()
        raise
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "SKU already exists or invalid related record") from exc
    finally:
        conn.close()


# ============================================================
# 22. POST /api/v1/admin/inventory/adjust - ADMIN
# ============================================================

@app.post("/api/v1/admin/inventory/adjust", tags=["Admin"])
def admin_adjust_inventory(
    data: InventoryAdjust,
    current_user=Depends(require_admin),
):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            variant = fetch_one(
                cursor,
                """
                SELECT id, stock_qty FROM product_variants
                WHERE id = %s FOR UPDATE
                """,
                (data.variant_id,),
            )
            if not variant:
                raise HTTPException(404, "Product variant not found")

            if data.type == "addition":
                new_stock = variant["stock_qty"] + data.quantity
                transaction_quantity = data.quantity
            elif data.type == "removal":
                if data.quantity > variant["stock_qty"]:
                    raise HTTPException(400, "Cannot remove more stock than available")
                new_stock = variant["stock_qty"] - data.quantity
                transaction_quantity = -data.quantity
            else:
                new_stock = data.quantity
                transaction_quantity = new_stock - variant["stock_qty"]

            cursor.execute(
                "UPDATE product_variants SET stock_qty = %s WHERE id = %s",
                (new_stock, data.variant_id),
            )
            cursor.execute(
                """
                INSERT INTO inventory_transactions
                (variant_id, type, quantity, reference_id)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    data.variant_id, data.type,
                    transaction_quantity, data.reference_id,
                ),
            )
        conn.commit()
        return {
            "message": "Inventory adjusted successfully",
            "variant_id": data.variant_id,
            "previous_stock": variant["stock_qty"],
            "current_stock": new_stock,
        }
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# RUN:
# uvicorn app.main:app --reload
# ============================================================



# ============================================================
# ADDITIONAL FRD MODULES: COUPONS / DISCOUNTS
# ============================================================

@app.get("/api/v1/coupons/validate", tags=["Coupons"])
def validate_coupon(code: str, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            coupon = fetch_one(
                cursor,
                """
                SELECT id, code, type, value, usage_limit, used_count, start_date, end_date
                FROM coupons
                WHERE code = %s AND status = 'active'
                  AND start_date <= NOW() AND end_date >= NOW()
                """,
                (code.strip().upper(),),
            )
            if not coupon:
                raise HTTPException(404, "Coupon is invalid, inactive, or expired")
            if coupon["usage_limit"] is not None and coupon["used_count"] >= coupon["usage_limit"]:
                raise HTTPException(400, "Coupon usage limit has been reached")
            cart = fetch_one(cursor, "SELECT id FROM carts WHERE user_id = %s AND status = 'active' ORDER BY id DESC LIMIT 1", (current_user["id"],))
            subtotal = Decimal("0.00")
            if cart:
                rows = fetch_all(cursor, "SELECT ci.quantity, pv.price FROM cart_items ci JOIN product_variants pv ON pv.id = ci.variant_id WHERE ci.cart_id = %s", (cart["id"],))
                subtotal = sum((Decimal(str(row["price"])) * row["quantity"] for row in rows), Decimal("0.00"))
            if coupon["type"] == "percentage":
                discount = (subtotal * Decimal(str(coupon["value"])) / Decimal("100")).quantize(Decimal("0.01"))
            else:
                discount = Decimal(str(coupon["value"])).quantize(Decimal("0.01"))
            discount = min(discount, subtotal)
            return {"valid": True, "code": coupon["code"], "discount_type": coupon["type"], "discount_value": coupon["value"], "estimated_discount": discount}
    finally:
        conn.close()


@app.post("/api/v1/admin/coupons", status_code=201, tags=["Admin", "Coupons"])
def admin_create_coupon(data: CouponCreate, current_user=Depends(require_admin)):
    if data.end_date <= data.start_date:
        raise HTTPException(400, "Coupon end_date must be after start_date")
    if data.type == "percentage" and data.value > 100:
        raise HTTPException(400, "Percentage coupon value cannot exceed 100")
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO coupons (code, type, value, start_date, end_date, usage_limit, status) VALUES (%s, %s, %s, %s, %s, %s, 'active')",
                (data.code.strip().upper(), data.type, data.value, data.start_date, data.end_date, data.usage_limit),
            )
            coupon_id = cursor.lastrowid
        conn.commit()
        return {"message": "Coupon created", "coupon_id": coupon_id}
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Coupon code already exists") from exc
    finally:
        conn.close()


# ============================================================
# ADDITIONAL FRD MODULES: ADDRESSES
# ============================================================

@app.get("/api/v1/addresses", tags=["Addresses"])
def list_addresses(current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            return fetch_all(
                cursor,
                "SELECT * FROM addresses WHERE user_id = %s ORDER BY id DESC",
                (current_user["id"],),
            )
    finally:
        conn.close()


@app.post("/api/v1/addresses", status_code=201, tags=["Addresses"])
def create_address(data: AddressCreate, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO addresses
                (user_id, type, full_name, phone, address_line1, address_line2,
                 city, state, postal_code, country)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    current_user["id"], data.type, data.full_name, data.phone,
                    data.address_line1, data.address_line2, data.city, data.state,
                    data.postal_code, data.country,
                ),
            )
            address_id = cursor.lastrowid
        conn.commit()
        return {"message": "Address created", "address_id": address_id}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.patch("/api/v1/addresses/{address_id}", tags=["Addresses"])
def update_address(address_id: int, data: AddressUpdate, current_user=Depends(require_customer)):
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(400, "No address fields supplied")
    allowed = {
        "type", "full_name", "phone", "address_line1", "address_line2",
        "city", "state", "postal_code", "country",
    }
    if not set(updates).issubset(allowed):
        raise HTTPException(400, "Invalid address fields")
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            address = fetch_one(
                cursor, "SELECT id FROM addresses WHERE id = %s AND user_id = %s",
                (address_id, current_user["id"]),
            )
            if not address:
                raise HTTPException(404, "Address not found")
            assignments = ", ".join(f"`{key}` = %s" for key in updates)
            cursor.execute(
                f"UPDATE addresses SET {assignments} WHERE id = %s AND user_id = %s",
                tuple(updates.values()) + (address_id, current_user["id"]),
            )
        conn.commit()
        return {"message": "Address updated"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.delete("/api/v1/addresses/{address_id}", tags=["Addresses"])
def delete_address(address_id: int, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM addresses WHERE id = %s AND user_id = %s",
                (address_id, current_user["id"]),
            )
            if cursor.rowcount == 0:
                raise HTTPException(404, "Address not found")
        conn.commit()
        return {"message": "Address deleted"}
    except HTTPException:
        conn.rollback()
        raise
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Address is used by an existing order and cannot be deleted") from exc
    finally:
        conn.close()


# ============================================================
# ADDITIONAL FRD MODULES: WISHLIST
# ============================================================

@app.get("/api/v1/wishlist", tags=["Wishlist"])
def view_wishlist(current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            wishlist = fetch_one(
                cursor, "SELECT id FROM wishlists WHERE user_id = %s",
                (current_user["id"],),
            )
            if not wishlist:
                cursor.execute("INSERT INTO wishlists (user_id) VALUES (%s)", (current_user["id"],))
                wishlist_id = cursor.lastrowid
                conn.commit()
            else:
                wishlist_id = wishlist["id"]
            return fetch_all(
                cursor,
                """
                SELECT wi.id AS wishlist_item_id, p.id AS product_id, p.name,
                       p.description, p.base_price, p.status
                FROM wishlist_items wi
                JOIN products p ON p.id = wi.product_id
                WHERE wi.wishlist_id = %s
                ORDER BY wi.id DESC
                """,
                (wishlist_id,),
            )
    finally:
        conn.close()


@app.post("/api/v1/wishlist/items", status_code=201, tags=["Wishlist"])
def add_wishlist_item(data: WishlistItemCreate, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            product = fetch_one(
                cursor, "SELECT id FROM products WHERE id = %s AND status = 'active'",
                (data.product_id,),
            )
            if not product:
                raise HTTPException(404, "Active product not found")
            wishlist = fetch_one(
                cursor, "SELECT id FROM wishlists WHERE user_id = %s",
                (current_user["id"],),
            )
            if not wishlist:
                cursor.execute("INSERT INTO wishlists (user_id) VALUES (%s)", (current_user["id"],))
                wishlist_id = cursor.lastrowid
            else:
                wishlist_id = wishlist["id"]
            cursor.execute(
                "INSERT INTO wishlist_items (wishlist_id, product_id) VALUES (%s, %s)",
                (wishlist_id, data.product_id),
            )
            item_id = cursor.lastrowid
        conn.commit()
        return {"message": "Product added to wishlist", "wishlist_item_id": item_id}
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Product is already in the wishlist") from exc
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.delete("/api/v1/wishlist/items/{item_id}", tags=["Wishlist"])
def remove_wishlist_item(item_id: int, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                DELETE wi FROM wishlist_items wi
                JOIN wishlists w ON w.id = wi.wishlist_id
                WHERE wi.id = %s AND w.user_id = %s
                """,
                (item_id, current_user["id"]),
            )
            if cursor.rowcount == 0:
                raise HTTPException(404, "Wishlist item not found")
        conn.commit()
        return {"message": "Wishlist item removed"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# ADDITIONAL FRD MODULES: NOTIFICATIONS
# ============================================================

@app.get("/api/v1/notifications", tags=["Notifications"])
def list_notifications(unread_only: bool = False, current_user=Depends(get_current_user)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            if unread_only:
                return fetch_all(
                    cursor,
                    "SELECT id, type, title, message, read_at, created_at FROM notifications WHERE user_id = %s AND read_at IS NULL ORDER BY created_at DESC",
                    (current_user["id"],),
                )
            return fetch_all(
                cursor,
                "SELECT id, type, title, message, read_at, created_at FROM notifications WHERE user_id = %s ORDER BY created_at DESC",
                (current_user["id"],),
            )
    finally:
        conn.close()


@app.patch("/api/v1/notifications/{notification_id}/read", tags=["Notifications"])
def mark_notification_read(notification_id: int, current_user=Depends(get_current_user)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE id = %s AND user_id = %s",
                (notification_id, current_user["id"]),
            )
            if cursor.rowcount == 0:
                raise HTTPException(404, "Notification not found")
        conn.commit()
        return {"message": "Notification marked as read"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# ADDITIONAL FRD MODULES: ADMIN CATEGORIES, USERS, REVIEWS, REPORTS
# ============================================================

@app.post("/api/v1/admin/categories", status_code=201, tags=["Admin"])
def admin_create_category(data: CategoryCreate, current_user=Depends(require_admin)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            if data.parent_id is not None and not fetch_one(cursor, "SELECT id FROM categories WHERE id = %s", (data.parent_id,)):
                raise HTTPException(404, "Parent category not found")
            cursor.execute(
                "INSERT INTO categories (parent_id, name, slug, status) VALUES (%s, %s, %s, %s)",
                (data.parent_id, data.name, data.slug, data.status),
            )
            category_id = cursor.lastrowid
        conn.commit()
        return {"message": "Category created", "category_id": category_id}
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Category slug already exists or parent is invalid") from exc
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.patch("/api/v1/admin/categories/{category_id}", tags=["Admin"])
def admin_update_category(category_id: int, data: CategoryUpdate, current_user=Depends(require_admin)):
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(400, "No category fields supplied")
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            if not fetch_one(cursor, "SELECT id FROM categories WHERE id = %s", (category_id,)):
                raise HTTPException(404, "Category not found")
            if updates.get("parent_id") == category_id:
                raise HTTPException(400, "A category cannot be its own parent")
            if updates.get("parent_id") is not None and not fetch_one(
                cursor, "SELECT id FROM categories WHERE id = %s", (updates["parent_id"],)
            ):
                raise HTTPException(404, "Parent category not found")
            columns = ", ".join(f"`{k}` = %s" for k in updates)
            cursor.execute(
                f"UPDATE categories SET {columns} WHERE id = %s",
                tuple(updates.values()) + (category_id,),
            )
        conn.commit()
        return {"message": "Category updated"}
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Category slug already exists") from exc
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/api/v1/admin/users", tags=["Admin"])
def admin_list_users(page: int = 1, page_size: int = 20, current_user=Depends(require_admin)):
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(400, "Invalid pagination values")
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            users = fetch_all(
                cursor,
                """
                SELECT u.id, u.name, u.email, u.phone, u.status, r.name AS role, u.created_at
                FROM users u JOIN roles r ON r.id = u.role_id
                ORDER BY u.created_at DESC LIMIT %s OFFSET %s
                """,
                (page_size, (page - 1) * page_size),
            )
            total = fetch_one(cursor, "SELECT COUNT(*) AS total FROM users")
        return {"page": page, "page_size": page_size, "total": total["total"], "users": users}
    finally:
        conn.close()


@app.patch("/api/v1/admin/users/{user_id}/status", tags=["Admin"])
def admin_update_user_status(user_id: int, data: UserStatusUpdate, current_user=Depends(require_admin)):
    if user_id == current_user["id"]:
        raise HTTPException(400, "You cannot change your own account status")
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET status = %s WHERE id = %s", (data.status, user_id))
            if cursor.rowcount == 0:
                exists = fetch_one(cursor, "SELECT id FROM users WHERE id = %s", (user_id,))
                if not exists:
                    raise HTTPException(404, "User not found")
        conn.commit()
        return {"message": "User status updated", "user_id": user_id, "status": data.status}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/api/v1/admin/reviews", tags=["Admin"])
def admin_list_reviews(review_status: Optional[Literal["pending", "approved", "rejected"]] = None,
                       current_user=Depends(require_admin)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            if review_status:
                return fetch_all(
                    cursor,
                    """
                    SELECT r.*, p.name AS product_name, u.name AS customer_name
                    FROM reviews r JOIN products p ON p.id = r.product_id
                    JOIN users u ON u.id = r.user_id
                    WHERE r.status = %s ORDER BY r.created_at DESC
                    """,
                    (review_status,),
                )
            return fetch_all(
                cursor,
                """
                SELECT r.*, p.name AS product_name, u.name AS customer_name
                FROM reviews r JOIN products p ON p.id = r.product_id
                JOIN users u ON u.id = r.user_id
                ORDER BY r.created_at DESC
                """,
            )
    finally:
        conn.close()


@app.patch("/api/v1/admin/reviews/{review_id}", tags=["Admin"])
def admin_moderate_review(review_id: int, data: ReviewModeration, current_user=Depends(require_admin)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE reviews SET status = %s WHERE id = %s", (data.status, review_id))
            if cursor.rowcount == 0 and not fetch_one(cursor, "SELECT id FROM reviews WHERE id = %s", (review_id,)):
                raise HTTPException(404, "Review not found")
        conn.commit()
        return {"message": "Review moderation updated"}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/api/v1/admin/reports/summary", tags=["Admin"])
def admin_report_summary(current_user=Depends(require_admin)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            return {
                "users": fetch_one(cursor, "SELECT COUNT(*) AS total FROM users")["total"],
                "active_products": fetch_one(cursor, "SELECT COUNT(*) AS total FROM products WHERE status = 'active'")["total"],
                "orders_by_status": fetch_all(cursor, "SELECT status, COUNT(*) AS total FROM orders GROUP BY status"),
                "revenue_from_successful_payments": fetch_one(
                    cursor,
                    "SELECT COALESCE(SUM(amount), 0) AS total FROM payments WHERE status = 'success'",
                )["total"],
                "low_stock_variants": fetch_all(
                    cursor,
                    """
                    SELECT pv.id AS variant_id, pv.sku, pv.stock_qty, p.name AS product_name
                    FROM product_variants pv JOIN products p ON p.id = pv.product_id
                    WHERE pv.stock_qty <= 5 ORDER BY pv.stock_qty ASC
                    """,
                ),
            }
    finally:
        conn.close()


# ============================================================
# ADDITIONAL FRD MODULES: ORDER PROCESSING AND SHIPMENT TRACKING
# ============================================================

_ORDER_TRANSITIONS = {
    "confirmed": {"processing"},
    "processing": {"packed"},
    "packed": {"shipped"},
    "shipped": {"out_for_delivery", "delivered"},
    "out_for_delivery": {"delivered"},
    "return_requested": {"returned"},
}


@app.patch("/api/v1/admin/orders/{order_id}/status", tags=["Admin"])
def admin_update_order_status(order_id: int, data: OrderStatusUpdate, current_user=Depends(require_operations)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(cursor, "SELECT id, user_id, status FROM orders WHERE id = %s FOR UPDATE", (order_id,))
            if not order:
                raise HTTPException(404, "Order not found")
            allowed = _ORDER_TRANSITIONS.get(order["status"], set())
            if data.status not in allowed:
                raise HTTPException(409, f"Invalid order transition: {order['status']} -> {data.status}")
            if data.status == "returned":
                returned_items = fetch_all(
                    cursor,
                    "SELECT variant_id, quantity FROM order_items WHERE order_id = %s",
                    (order_id,),
                )
                for item in returned_items:
                    cursor.execute(
                        "UPDATE product_variants SET stock_qty = stock_qty + %s WHERE id = %s",
                        (item["quantity"], item["variant_id"]),
                    )
                    cursor.execute(
                        """
                        INSERT INTO inventory_transactions (variant_id, type, quantity, reference_id)
                        VALUES (%s, 'customer_return', %s, %s)
                        """,
                        (item["variant_id"], item["quantity"], order_id),
                    )

            cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (data.status, order_id))
            cursor.execute(
                """
                INSERT INTO order_status_history
                    (order_id, old_status, new_status, changed_by_user_id, note)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (order_id, order["status"], data.status, current_user["id"], data.note),
            )
            if data.status == "delivered":
                add_notification(cursor, order["user_id"], "order", "Order delivered", f"Order #{order_id} has been delivered.")
        conn.commit()
        return {"message": "Order status updated", "order_id": order_id, "status": data.status}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.post("/api/v1/admin/orders/{order_id}/shipment", status_code=201, tags=["Admin"])
def admin_create_shipment(order_id: int, data: ShipmentCreate, current_user=Depends(require_operations)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(cursor, "SELECT id, user_id, status FROM orders WHERE id = %s FOR UPDATE", (order_id,))
            if not order:
                raise HTTPException(404, "Order not found")
            if order["status"] not in ("packed", "shipped"):
                raise HTTPException(409, "A shipment can only be created for a packed or shipped order")
            existing = fetch_one(cursor, "SELECT id FROM shipments WHERE order_id = %s", (order_id,))
            if existing:
                raise HTTPException(409, "A shipment already exists for this order")
            cursor.execute(
                "INSERT INTO shipments (order_id, carrier, tracking_no, status) VALUES (%s, %s, %s, 'shipped')",
                (order_id, data.carrier, data.tracking_no),
            )
            shipment_id = cursor.lastrowid
            if order["status"] == "packed":
                cursor.execute("UPDATE orders SET status = 'shipped' WHERE id = %s", (order_id,))
                cursor.execute(
                    """
                    INSERT INTO order_status_history (order_id, old_status, new_status, changed_by_user_id, note)
                    VALUES (%s, 'packed', 'shipped', %s, %s)
                    """,
                    (order_id, current_user["id"], f"Shipment created: {data.tracking_no}"),
                )
            add_notification(cursor, order["user_id"], "shipment", "Shipment created", f"Tracking number: {data.tracking_no}")
        conn.commit()
        return {"message": "Shipment created", "shipment_id": shipment_id, "tracking_no": data.tracking_no}
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        raise HTTPException(409, "Tracking number already exists") from exc
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.patch("/api/v1/admin/shipments/{shipment_id}/status", tags=["Admin"])
def admin_update_shipment_status(shipment_id: int, shipment_status: Literal["shipped", "in_transit", "out_for_delivery", "delivered", "failed", "returned"],
                                 current_user=Depends(require_operations)):
    mapping = {
        "shipped": "shipped",
        "in_transit": "shipped",
        "out_for_delivery": "out_for_delivery",
        "delivered": "delivered",
        "failed": None,
        "returned": "returned",
    }
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            shipment = fetch_one(
                cursor,
                """
                SELECT s.id, s.order_id, o.user_id, o.status AS order_status
                FROM shipments s JOIN orders o ON o.id = s.order_id
                WHERE s.id = %s FOR UPDATE
                """,
                (shipment_id,),
            )
            if not shipment:
                raise HTTPException(404, "Shipment not found")
            cursor.execute("UPDATE shipments SET status = %s WHERE id = %s", (shipment_status, shipment_id))
            next_order_status = mapping[shipment_status]
            valid_shipment_order_states = {
                "shipped": {"packed", "shipped"},
                "in_transit": {"shipped"},
                "out_for_delivery": {"shipped", "out_for_delivery"},
                "delivered": {"shipped", "out_for_delivery", "delivered"},
                "returned": {"return_requested", "returned"},
                "failed": set(),
            }
            if shipment["order_status"] not in valid_shipment_order_states[shipment_status]:
                raise HTTPException(
                    409,
                    f"Shipment status {shipment_status} is not valid for order status {shipment['order_status']}",
                )
            if next_order_status and next_order_status != shipment["order_status"]:
                old = shipment["order_status"]
                if next_order_status == "returned":
                    returned_items = fetch_all(
                        cursor,
                        "SELECT variant_id, quantity FROM order_items WHERE order_id = %s",
                        (shipment["order_id"],),
                    )
                    for item in returned_items:
                        cursor.execute(
                            "UPDATE product_variants SET stock_qty = stock_qty + %s WHERE id = %s",
                            (item["quantity"], item["variant_id"]),
                        )
                        cursor.execute(
                            "INSERT INTO inventory_transactions (variant_id, type, quantity, reference_id) VALUES (%s, 'customer_return', %s, %s)",
                            (item["variant_id"], item["quantity"], shipment["order_id"]),
                        )
                cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (next_order_status, shipment["order_id"]))
                cursor.execute(
                    """
                    INSERT INTO order_status_history (order_id, old_status, new_status, changed_by_user_id, note)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (shipment["order_id"], old, next_order_status, current_user["id"], f"Shipment status: {shipment_status}"),
                )
                add_notification(cursor, shipment["user_id"], "shipment", "Shipment update", f"Your order #{shipment['order_id']} is {shipment_status.replace('_', ' ')}.")
        conn.commit()
        return {"message": "Shipment status updated", "shipment_status": shipment_status}
    except HTTPException:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/api/v1/orders/{order_id}/tracking", tags=["Orders"])
def track_order(order_id: int, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(
                cursor,
                "SELECT id FROM orders WHERE id = %s AND user_id = %s",
                (order_id, current_user["id"]),
            )
            if not order:
                raise HTTPException(404, "Order not found")
            return fetch_all(
                cursor,
                """
                SELECT carrier, tracking_no, status, created_at, updated_at
                FROM shipments WHERE order_id = %s ORDER BY created_at DESC
                """,
                (order_id,),
            )
    finally:
        conn.close()



@app.get("/api/v1/orders/{order_id}/history", tags=["Orders"])
def customer_order_status_history(order_id: int, current_user=Depends(require_customer)):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            order = fetch_one(
                cursor,
                "SELECT id FROM orders WHERE id = %s AND user_id = %s",
                (order_id, current_user["id"]),
            )
            if not order:
                raise HTTPException(404, "Order not found")
            return fetch_all(
                cursor,
                """
                SELECT old_status, new_status, note, created_at
                FROM order_status_history
                WHERE order_id = %s
                ORDER BY created_at ASC, id ASC
                """,
                (order_id,),
            )
    finally:
        conn.close()
