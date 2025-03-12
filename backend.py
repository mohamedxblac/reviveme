from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
import datetime
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

# إعداد التطبيق
app = Flask(__name__, instance_path='/build/instance')
CORS(app)  # للسماح بطلبات من الواجهة الأمامية

# إعداد قاعدة البيانات
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reviveme.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ------------------- نماذج قاعدة البيانات -------------------

# نموذج المستخدم
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    join_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_check_in = db.Column(db.DateTime, nullable=True)
    profile_image = db.Column(db.String(255), nullable=True)
    progress_start_date = db.Column(db.DateTime, nullable=True)
    current_goal = db.Column(db.Integer, default=7)  
    
    # العلاقات
    clean_days = db.relationship('CleanDay', backref='user', lazy=True)
    daily_checks = db.relationship('DailyCheck', backref='user', lazy=True)
    relapses = db.relationship('Relapse', backref='user', lazy=True)
    tasks = db.relationship('Task', backref='user', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'join_date': self.join_date.isoformat() if self.join_date else None,
            'last_check_in': self.last_check_in.isoformat() if self.last_check_in else None,
            'profile_image': self.profile_image,
            'progress_start_date': self.progress_start_date.isoformat() if self.progress_start_date else None,
            'current_goal': self.current_goal
        }

# نموذج يوم نظيف
class CleanDay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat(),
            'user_id': self.user_id
        }

# نموذج الفحص اليومي
class DailyCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mood = db.Column(db.String(50), nullable=True)
    urge_level = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat(),
            'user_id': self.user_id,
            'mood': self.mood,
            'urge_level': self.urge_level,
            'notes': self.notes
        }

# نموذج الانتكاسة
class Relapse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    trigger = db.Column(db.Text, nullable=True)
    feelings = db.Column(db.Text, nullable=True)
    circumstances = db.Column(db.Text, nullable=True)
    lessons = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat(),
            'user_id': self.user_id,
            'trigger': self.trigger,
            'feelings': self.feelings,
            'circumstances': self.circumstances,
            'lessons': self.lessons
        }

# نموذج المهمة اليومية
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    frequency = db.Column(db.String(50), default="daily")  # daily, weekly, monthly
    is_completed = db.Column(db.Boolean, default=False)
    last_completed = db.Column(db.DateTime, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'user_id': self.user_id,
            'frequency': self.frequency,
            'is_completed': self.is_completed,
            'last_completed': self.last_completed.isoformat() if self.last_completed else None
        }

# ------------------- وظائف مساعدة -------------------

def generate_token(user_id):
    """
    توليد رمز JWT للمستخدم
    """
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
        'iat': datetime.datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        app.config.get('SECRET_KEY'),
        algorithm='HS256'
    )

def token_required(f):
    """
    زخرفة للتحقق من صحة الرمز
    """
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token is invalid'}), 401
                
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
            
        try:
            data = jwt.decode(token, app.config.get('SECRET_KEY'), algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['sub']).first()
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except Exception as e:
            return jsonify({'message': f'Token is invalid: {str(e)}'}), 401
            
        return f(current_user, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# وظيفة مساعدة لحساب عدد الأيام النظيفة
def calculate_clean_days(user):
    """
    حساب عدد الأيام النظيفة للمستخدم منذ آخر انتكاسة
    """
    # البحث عن آخر انتكاسة
    last_relapse = Relapse.query.filter_by(user_id=user.id).order_by(Relapse.date.desc()).first()
    
    if last_relapse:
        # حساب الأيام منذ آخر انتكاسة
        start_date = last_relapse.date.date()
    elif user.progress_start_date:
        # إذا لم تكن هناك انتكاسة، استخدم تاريخ بدء التقدم
        start_date = user.progress_start_date.date()
    else:
        # إذا لم يكن هناك تاريخ بدء، استخدم تاريخ الانضمام
        start_date = user.join_date.date()
    
    # حساب الفرق بالأيام بين اليوم وتاريخ البداية
    today = datetime.datetime.utcnow().date()
    days_diff = (today - start_date).days
    
    return max(0, days_diff)  # لا يمكن أن يكون عدد الأيام بالسالب

# وظيفة مساعدة لتحديث هدف المستخدم بناءً على تقدمه
def update_user_goal(user, days_clean):
    """
    تحديث هدف المستخدم بناءً على عدد الأيام النظيفة
    """
    goals = [7, 14, 30, 90, 180, 365]
    
    # تحديد الهدف المناسب
    for goal in goals:
        if days_clean < goal:
            if user.current_goal != goal:
                user.current_goal = goal
                db.session.commit()
            return goal
    
    # إذا تجاوز جميع الأهداف، استخدم الهدف النهائي
    if user.current_goal != goals[-1]:
        user.current_goal = goals[-1]
        db.session.commit()
    
    return goals[-1]

# ------------------- طرق API -------------------

# طريقة الاختبار الأساسي
@app.route('/api/test', methods=['GET'])
def test_api():
    return jsonify({'message': 'API is working!'}), 200

# تسجيل مستخدم جديد
@app.route('/api/users/register', methods=['POST'])
def register_user():
    data = request.get_json()
    
    # التحقق من وجود البيانات المطلوبة
    if not data or not data.get('email') or not data.get('password') or not data.get('username'):
        return jsonify({'message': 'Missing required data'}), 400
        
    # التحقق من عدم وجود المستخدم مسبقاً
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'message': 'User already exists with this email'}), 409
        
    # إنشاء مستخدم جديد
    hashed_password = generate_password_hash(data.get('password'))
    new_user = User(
        username=data.get('username'),
        email=data.get('email'),
        password=hashed_password,
        progress_start_date=datetime.datetime.utcnow()
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    # توليد رمز JWT
    token = generate_token(new_user.id)
    
    return jsonify({
        'message': 'User registered successfully',
        'token': token,
        'user': new_user.to_dict()
    }), 201

# تسجيل دخول المستخدم
@app.route('/api/users/login', methods=['POST'])
def login_user():
    data = request.get_json()
    
    # التحقق من وجود البيانات المطلوبة
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
        
    # البحث عن المستخدم
    user = User.query.filter_by(email=data.get('email')).first()
    
    # التحقق من وجود المستخدم وصحة كلمة المرور
    if not user or not check_password_hash(user.password, data.get('password')):
        return jsonify({'message': 'Invalid email or password'}), 401
        
    # توليد رمز JWT
    token = generate_token(user.id)
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': user.to_dict()
    }), 200

# الحصول على معلومات المستخدم
@app.route('/api/users/me', methods=['GET'])
@token_required
def get_user_info(current_user):
    return jsonify({
        'user': current_user.to_dict()
    }), 200

# ------------ نقاط نهاية جديدة لتتبع التقدم ------------

# الحصول على الأيام النظيفة وإحصائيات التقدم
@app.route('/api/progress/clean-days', methods=['GET'])
@token_required
def get_clean_days_progress(current_user):
    """
    الحصول على عدد الأيام النظيفة وإحصائيات التقدم
    """
    # حساب عدد الأيام النظيفة
    days_clean = calculate_clean_days(current_user)
    
    # تحديث هدف المستخدم إذا لزم الأمر
    current_goal = update_user_goal(current_user, days_clean)
    
    # حساب الإحصائيات الإضافية
    weeks_clean = days_clean // 7
    months_clean = days_clean // 30
    
    # تحديد الهدف التالي
    goals = [7, 14, 30, 90, 180, 365]
    next_goal = next((goal for goal in goals if goal > days_clean), 365)
    
    # إعداد استجابة مفصلة
    response = {
        'days_clean': days_clean,
        'weeks_clean': weeks_clean,
        'months_clean': months_clean,
        'current_goal': current_goal,
        'next_goal': next_goal,
        'progress_percentage': (days_clean / current_goal * 100) if current_goal > 0 else 0,
        'start_date': current_user.progress_start_date.isoformat() if current_user.progress_start_date else current_user.join_date.isoformat()
    }
    
    return jsonify(response), 200

# إضافة أو تحديث الفحص اليومي
@app.route('/api/daily-check', methods=['POST'])
@token_required
def add_daily_check(current_user):
    """
    إضافة فحص يومي جديد
    """
    data = request.get_json()
    
    # التحقق من وجود البيانات المطلوبة
    if not data:
        return jsonify({'message': 'No data provided'}), 400
    
    # التحقق مما إذا كان هناك فحص يومي سابق لهذا اليوم
    today = datetime.datetime.utcnow().date()
    existing_check = DailyCheck.query.filter_by(
        user_id=current_user.id,
        date=today
    ).first()
    
    if existing_check:
        # تحديث الفحص اليومي الموجود
        if 'mood' in data:
            existing_check.mood = data.get('mood')
        if 'urge_level' in data:
            existing_check.urge_level = data.get('urge_level')
        if 'notes' in data:
            existing_check.notes = data.get('notes')
        
        db.session.commit()
        
        return jsonify({
            'message': 'Daily check updated successfully',
            'daily_check': existing_check.to_dict()
        }), 200
    else:
        # إنشاء فحص يومي جديد
        new_check = DailyCheck(
            date=today,
            user_id=current_user.id,
            mood=data.get('mood'),
            urge_level=data.get('urge_level'),
            notes=data.get('notes')
        )
        
        # تحديث آخر تسجيل دخول للمستخدم
        current_user.last_check_in = datetime.datetime.utcnow()
        
        # إضافة يوم نظيف جديد إذا لم يكن موجوداً بالفعل
        existing_clean_day = CleanDay.query.filter_by(
            user_id=current_user.id,
            date=today
        ).first()
        
        if not existing_clean_day:
            new_clean_day = CleanDay(
                date=today,
                user_id=current_user.id
            )
            db.session.add(new_clean_day)
        
        db.session.add(new_check)
        db.session.commit()
        
        return jsonify({
            'message': 'Daily check added successfully',
            'daily_check': new_check.to_dict()
        }), 201

# الحصول على سجل الفحوصات اليومية
@app.route('/api/daily-checks/history', methods=['GET'])
@token_required
def get_daily_checks_history(current_user):
    """
    الحصول على سجل الفحوصات اليومية للمستخدم
    """
    # الحصول على الفحوصات اليومية مرتبة حسب التاريخ
    checks = DailyCheck.query.filter_by(
        user_id=current_user.id
    ).order_by(DailyCheck.date.desc()).all()
    
    return jsonify({
        'daily_checks': [check.to_dict() for check in checks]
    }), 200

# تسجيل انتكاسة
@app.route('/api/relapse', methods=['POST'])
@token_required
def add_relapse(current_user):
    """
    تسجيل انتكاسة جديدة
    """
    data = request.get_json()
    
    # التحقق من وجود البيانات
    if not data:
        return jsonify({'message': 'No data provided'}), 400
    
    # إنشاء انتكاسة جديدة
    new_relapse = Relapse(
        user_id=current_user.id,
        trigger=data.get('trigger'),
        feelings=data.get('feelings'),
        circumstances=data.get('circumstances'),
        lessons=data.get('lessons')
    )
    
    # تحديث تاريخ بدء التقدم للمستخدم
    current_user.progress_start_date = datetime.datetime.utcnow()
    
    db.session.add(new_relapse)
    db.session.commit()
    
    return jsonify({
        'message': 'Relapse recorded successfully',
        'relapse': new_relapse.to_dict()
    }), 201

# الحصول على سجل الانتكاسات
@app.route('/api/relapses/history', methods=['GET'])
@token_required
def get_relapse_history(current_user):
    """
    الحصول على سجل الانتكاسات للمستخدم
    """
    # الحصول على الانتكاسات مرتبة حسب التاريخ
    relapses = Relapse.query.filter_by(
        user_id=current_user.id
    ).order_by(Relapse.date.desc()).all()
    
    return jsonify({
        'relapses': [relapse.to_dict() for relapse in relapses]
    }), 200

# ------------------- تشغيل التطبيق -------------------

# إنشاء الجداول قبل تشغيل التطبيق
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000) 