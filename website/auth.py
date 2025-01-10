import hashlib
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from hashlib import sha256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend



backend = default_backend()
digest = hashes.Hash(hashes.SHA256(), backend=backend)
digest.update(b'some_data_to_hash')
hashed_data = digest.finalize()
data = "some_data_to_hash"
data_bytes = data.encode('utf-8')
hashed_data = hashlib.sha256(data_bytes).hexdigest()

"""
Создаение объект бэкенда, который управляет низкоуровневыми операциями криптографии.
Создание объект хэш-функции с использованием алгоритма SHA-256.
Данные, которые нужно захешировать, передаются в виде байтов методом update.
Метод finalize завершает процесс хеширования и возвращает результат в виде байтового массива.
Строковые данные преобразуются в байтовый массив с использованием кодировки UTF-8.
Метод sha256 из модуля hashlib применяется к байтовым данным, а метод hexdigest возвращает результат в виде шестнадцатеричной строки.
"""

auth = Blueprint('auth', __name__)
""" В этой строке кода создается экземпляр Blueprint под названием auth для приложения Flask. 
Blueprint позволяет группировать маршруты и другие компоненты приложения в отдельные модули, что упрощает организацию большого проекта."""

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)
"""
Этот фрагмент кода реализует маршрут /login для обработки формы входа пользователя в системе.
Маршрут /login доступен для методов GET и POST. Метод GET используется для отображения страницы входа, а метод POST — для отправки данных формы.
Если запрос был отправлен методом POST, значит, пользователь отправил форму для входа.
Извлечение значений полей email и password из формы.
Выполняется поиск пользователя в базе данных по указанному email. Если такой пользователь существует, возвращается объект User, иначе — None.
Если пользователь найден, продолжается проверка пароля.
Пароль, отправленный пользователем, сравнивается с хранимым хешем пароля. Если пароли совпадают, выполнение продолжается.
Сообщение об успешном входе отправляется пользователю, выполняется вход с помощью login_user, и пользователь перенаправляется на домашнюю страницу.
Если пароль неверен, пользователю показывается соответствующее сообщение об ошибке.
Если пользователь с таким email не найден, пользователю показывается сообщение об ошибке.
Независимо от результатов проверки, страница входа снова рендерится. Также передается информация о текущем пользователе через контекстную переменную user.
Этот код обеспечивает безопасную проверку данных пользователя и управление процессом входа в систему
"""

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

"""
Этот фрагмент кода реализует маршрут /logout для выхода пользователя из системы. 
Декоратор требует, чтобы пользователь был авторизован для доступа к маршруту. Если пользователь не вошел в систему, он будет перенаправлен на страницу входа.
Когда пользователь посещает маршрут /logout, вызывается функция logout_user(), которая удаляет информацию о 
текущем пользователе из сессии. Затем пользователь перенаправляется обратно на страницу входа.
"""

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        """
        В этом фрагменте кода происходит обработка POST-запроса для регистрации нового пользователя
        """

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sing_up.html", user=current_user)


"""
Импорты 
import hashlib
Модуль `hashlib` предоставляет инструменты для вычисления криптографических хешей, таких как SHA-256. Он часто используется для безопасного хранения паролей.

from flask import Blueprint, render_template, request, flash, redirect, url_for
Blueprint: Используется для создания blueprints, позволяющих организовывать маршруты и ресурсы в приложении.
render_template: Рендеринг HTML-шаблонов.
request: Доступ к данным HTTP-запросов.
flash: Отправка сообщений пользователям.
redirect: Перенаправление на другой URL.
url_for: Генерация URL по имени маршрута.

from .models import User
from . import db
Импортируется модель `User` и объект `db` (SQLAlchemy), который используется для работы с базой данных.

from werkzeug.security import generate_password_hash, check_password_hash
Функции для генерации и проверки хешированных паролей. Они используются для безопасного хранения и проверки паролей.


from flask_login import login_user, login_required, logout_user, current_user
Классы и методы для управления сессией пользователя:
login_user: Вход пользователя в систему.
login_required: Декоратор для защиты маршрутов от доступа незарегистрированных пользователей.
logout_user: Выход пользователя из системы.
current_user: Текущий пользователь, вошедший в систему.


from hashlib import sha256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
Эти импорты предоставляют дополнительные возможности для работы с криптографическими хешами и алгоритмами шифрования.
"""
