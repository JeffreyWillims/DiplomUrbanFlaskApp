from website import create_app


app = create_app()


if __name__ == '__main__':
    app.run(debug=True)

"""
Этот код выполняет несколько важных шагов для запуска веб-приложения на основе фреймворка Flask:
Импорт create_app:
Здесь импортируется функция create_app, которая находится в модуле website. Эта функция обычно отвечает за создание 
экземпляра приложения Flask, а также за настройку различных компонентов приложения, таких как базы данных, маршруты, шаблоны и так далее.

Вызывается функция create_app(), чтобы создать экземпляр приложения Flask. Этот объект будет содержать все настройки и компоненты вашего веб-приложения.
if __name__ == '__main__':
       app.run(debug=True)
   
Этот блок кода проверяет, запущен ли скрипт непосредственно (то есть не является импортированным модулем). 
Если условие выполняется (__name__ равно '__main__'), то приложение запускается локально с помощью метода run() с параметром debug=True.
   
Параметр debug=True включает режим отладки, который полезен при разработке, поскольку он 
автоматически перезапускает сервер при изменении файлов и выводит подробные сообщения об ошибках в браузер.

Таким образом, этот код инициализирует и запускает ваше веб-приложение Flask, позволяя вам тестировать его локально перед развертыванием.
"""