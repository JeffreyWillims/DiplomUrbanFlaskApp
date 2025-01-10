from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import Note
from . import db
import json

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')#Gets the note from the HTML

        if len(note) < 1:
            flash('Note is too short!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)  #providing the schema for the note
            db.session.add(new_note) #adding the note to the database
            db.session.commit()
            flash('Note added!', category='success')

    return render_template("home.html", user=current_user)
"""
Фрагмент кода определяет маршрут для главной страницы (/) и реализует функциональность добавления заметок пользователями
@views.route('/'): Определяет маршрут для главной страницы (/). Метод route указывает, что данная функция будет отвечать за обработку запросов к этому маршруту.
methods=['GET', 'POST']: Указывает, что маршрут поддерживает методы GET и POST. GET используется для получения данных, а POST — для отправки данных на сервер.
@login_required: Декоратор, который требует, чтобы пользователь был аутентифицирован, прежде чем получить доступ к этой странице.
Если пользователь не вошел в систему, он будет перенаправлен на страницу входа.
Проверяем, является ли текущий запрос методом POST. Если да, значит пользователь отправил форму с данными.
Извлекает значение поля note из формы, отправленной методом POST. Это значение отправляется пользователем через HTML-форму
Проверяет длину заметки. Если она меньше одного символа, выводит сообщение об ошибке с помощью функции flash.
Категория error указывает, что это ошибка, которую нужно показать пользователю.
Новая заметка добавляется в сессию базы данных с помощью метода add, а затем изменения фиксируются с помощью commit.
Независимо от того, был ли запрос методом GET или POST, возвращается шаблон home.html, 
в котором передается информация о текущем пользователе через параметр user=current_user.
"""

@views.route('/delete-note', methods=['POST'])
def delete_note():
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})

"""
Данный фрагмент кода создаёт маршрут для удаления заметки.
Здесь определяется маршрут /delete-note, который принимает только POST-запросы. Это означает, 
что данный маршрут предназначен для обработки запросов на удаление заметки.
Функция ожидает получение данных в формате JSON от клиента (например, из JavaScript-файла). 
Эти данные загружаются с использованием json.loads(), который преобразует строку JSON в Python-объект.
Из полученного JSON извлекается значение ключа noteId, которое соответствует идентификатору заметки, которую нужно удалить
Запрашивает заметку из базы данных по её идентификатору с помощью ORM SQLAlchemy.
После завершения всех операций функция возвращает пустой JSON-объект. Это делается для того, 
чтобы клиент получил подтверждение о завершении операции без передачи каких-либо дополнительных данных.
"""