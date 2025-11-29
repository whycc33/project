import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# --- 1. Configuration ---
app = Flask(__name__)
# Secret key for session security (Keep this secret in production!)
app.config['SECRET_KEY'] = 'hsu-canteen-secret-key-2024'
# Database configuration (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hsu_canteen.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Internal API Token for security (Requirement: Secure Internal API)
INTERNAL_API_TOKEN = "HSU-SECURE-TOKEN-888"

# --- 2. Database Models ---

# User Model: Stores HSU Student Data
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False) # Security: Hashed password
    
    # HSU Specific Fields (Requirement: Secure HSU Data Storage)
    is_hsu_member = db.Column(db.Boolean, default=False)
    student_id = db.Column(db.String(20), nullable=True)
    programme = db.Column(db.String(100), nullable=True) # e.g., BA-AHCC
    admission_year = db.Column(db.Integer, nullable=True)

# MenuItem Model: Real menu items and prices
class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False) # Base price
    category = db.Column(db.String(50), nullable=False) # Breakfast, Lunch, Tea
    image_url = db.Column(db.String(300), default='https://placehold.co/400x300?text=Food') # Placeholder
    is_available = db.Column(db.Boolean, default=True)

# Order Model: Connects Users to Orders
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Status flow: Pending -> Cooking -> Ready -> Completed
    status = db.Column(db.String(50), default='Pending') 
    total_price = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to items
    items = db.relationship('OrderItem', backref='order', lazy=True)

# OrderItem Model: Handles complex customization logic
class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    menu_item_name = db.Column(db.String(150)) # Snapshot of name at time of order
    quantity = db.Column(db.Integer, default=1)
    
    # Stores customization text, e.g., "Iced Drink (+$2.0)"
    customization = db.Column(db.String(300), nullable=True) 
    item_price_at_order = db.Column(db.Float, nullable=False) # Final price per unit

# --- 3. Helper Functions ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 4. Setup Route (One-time use to create DB) ---
@app.route('/setup')
def setup_database():
    """Creates the database and populates it with the REAL HSU Menu items."""
    with app.app_context():
        db.create_all()
        
        # Check if menu already exists to avoid duplicates
        if not MenuItem.query.first():
            # Create Real Menu Items from your requirements
            items = [
                MenuItem(name="Hot Cake Breakfast", price=34.00, category="Breakfast"),
                MenuItem(name="Two Dishes with Rice", price=35.00, category="Lunch"),
                MenuItem(name="Pork Chop Bun", price=42.00, category="Tea"), # Tea set price
                MenuItem(name="Curry Beef Brisket", price=45.00, category="Lunch")
            ]
            db.session.add_all(items)
            db.session.commit()
            return "Database initialized with HSU Menu Items!"
        return "Database already exists."

# --- 5. Main Routes ---
@app.route('/')
def index():
    # Fetch all menu items from the database
    items = MenuItem.query.all()
    # Send them to the HTML file
    return render_template('index.html', items=items)
# --- 6. Auth Routes (Register & Login) ---
# 这一部分是您缺失的代码，导致了报错

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 获取表单数据
        username = request.form.get('username')
        password = request.form.get('password')
        student_id = request.form.get('student_id')
        programme = request.form.get('programme')
        year = request.form.get('admission_year')

        # 检查用户是否存在
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        # 安全性：哈希加密密码
        hashed_pw = generate_password_hash(password, method='scrypt') 
        # 注意: 如果您的 python 版本较老报错，可以将 'scrypt' 改为 'sha256'

        # 创建新用户
        new_user = User(
            username=username, 
            password_hash=hashed_pw,
            student_id=student_id,
            programme=programme,
            admission_year=year,
            is_hsu_member=True if student_id else False
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # 验证密码
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            
            # 如果用户之前是因为点击"下单"被强制跳转过来的，登录后送他回去
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login failed. Check username and password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- 7. Ordering Logic (Complex Customization) ---

@app.route('/add_to_order/<int:item_id>', methods=['POST'])
@login_required  # 确保只有登录用户能访问
def add_to_order(item_id):
    # 1. 获取菜品信息
    item = MenuItem.query.get_or_404(item_id)
    
    # 2. 获取用户勾选的加配项 (Customization)
    custom_options = []
    current_price = item.price
    
    # 检查是否选了冻饮 (Iced Drink +$2)
    if 'iced_drink' in request.form:
        current_price += 2.0
        custom_options.append("Iced Drink (+$2.0)")
        
    # 检查是否加了咸蛋 (Salted Egg +$4)
    if 'salted_egg' in request.form:
        current_price += 4.0
        custom_options.append("Salted Egg (+$4.0)")
        
    # 将列表转换为字符串存储
    custom_str = ", ".join(custom_options) if custom_options else "Standard"

    # 3. 查找或创建当前用户的"Pending"订单
    # 我们只查找状态为 'Pending' 或 'Cooking' 的订单，如果只有完成的订单，就开新单
    current_order = Order.query.filter_by(user_id=current_user.id, status='Pending').first()
    
    if not current_order:
        current_order = Order(user_id=current_user.id, status='Pending', total_price=0)
        db.session.add(current_order)
        db.session.commit() # 提交以获取 Order ID
    
    # 4. 创建订单详情 (Order Item)
    new_item = OrderItem(
        order_id=current_order.id,
        menu_item_id=item.id,
        menu_item_name=item.name,
        quantity=1,
        customization=custom_str,
        item_price_at_order=current_price
    )
    
    # 5. 更新总价并保存
    db.session.add(new_item)
    current_order.total_price += current_price
    db.session.commit()
    
    flash(f'Added {item.name} to your order!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)