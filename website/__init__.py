from flask import Flask
from flask_login import LoginManager, UserMixin
from os import path
from bson import ObjectId
from .Database import Database

class User(UserMixin):
    def __init__(self, user):
        self.id = str(user['_id'])
        self.username = user['username']
        self.password = user['password']

# This class will likely grow and should at that point become an import in it's own module
class Config():
    def __init__(self):
        self.db_user = ""
        self.db_password = ""
        self.db_name = "subliminal_test"
        self.db_ip = "127.0.0.1"
        self.db_port = 27017

db = Database(Config())

#db = SQLAlchemy()
#DB_NAME = "database.db"
# import views
from .views import views
from .auth import auth
# import modles

def create_app():
    """ Initialize flask application """
    # The Flask class implements WSGI app and acts as the central object
    # Acts as central regsitry of view functions, URL rules, templates etc...
    app = Flask(__name__)
    
    # The secret key is used to encrypt session keys etc
    app.config['SECRET_KEY'] = b'b\x11\x19\xd8\xda\x8b<)2N?\x14\x86\x95\xba\x90"(\x96J\xd0\xa7\x9f=\xfde\x0fpI\xcaw\xb9\xbflK6\x13\xbdl\xe8\xf1\xdb\xe7x\xee$\xc14l\xbc"\xdd\x01\xbf\xd0\x1c\xc2\x10\xd7~l\xf2L0\x06\x16[\x07\xe9\\\xf6\x8c\x1a\x81\x17\xeb|-\xad\x95>\x85\x92\x95Y\xfac}6\xcf6\xdd\x963\xf8qw5\xb8z\xdd\xd7\xcf\xdc<[\xbcidXG\xdf\xc8\x9a\x98\xb7\xc4\xf9\xe0\xcb\xfd%\x99\xb5>\x16\x80\xca\xf1\xa8\xea\t\xba\x9c\xf0\xbd\x88\xdb\xa5/\'\xcfY\xa5\xe5~\xab?.\x07\xe0\x07\xad\xd2\x87\xef\xa0\x07\xfc\xcf\x11a\x97\xfaf\xe2\xcf\xa4\x1e\x87\x84\xf3\x1d.3i\x8df\tOg\xf8\xb3Md\x8f\x87\x8e\xae\xec\xbc\x0f\x11UlLdB\xa7\xf61mqK\x84\x02i;2\xa3\xd8\xbe\x1dO\xe8|\xe6=\x98X\xafC\xe8\x07V!d\xaa\xef\xd8;n\xb1G\x99lE\x00cf\xeaw\xc4k\x181\x95\xd9\xb5&;>Z\xf9\xd7+' 

    # configure database
    # app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    # db.init_app(app)

    
    # register blueprints so that flask knows about our externally defined views
    # Note prefix will be make the rule be defined relative to that prefix 
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    #create_database(app)
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    @login_manager.user_loader
    def load_user(id):
        return User(db.read_user(user_id=ObjectId(id)))
    return app

"""
def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created database')
"""
