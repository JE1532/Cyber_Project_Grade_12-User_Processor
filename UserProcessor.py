import sqlite3


DATABASE_FILE = 'songTestV1.db'
CREATE_USER_TABLE = """CREATE TABLE users(
             username_hash VARCHAR(64),
             password_hash VARCHAR(64),
             email VARCHAR(30),
             PRIMARY KEY(username_hash));"""
DROP_USER_TABLE ="DROP TABLE users"
SELECT = lambda table, fields, condition : str.format("SELECT {} FROM {} WHERE {};", fields, table, condition)
INSERT = lambda table, values : str.format('INSERT INTO {} VALUES({});', table, values)

LOG_NEW_USER = "UserProcessor/Sign_up?"
LOG_RETURNING_USER = "UserProcessor/Sign_in?"

USER_ALREADY_EXISTS = 'user_already_exists'
WRONG_PASSWORD = 'wrong_password'
AUTH_OKAY = '200'


class UserProcessor:
    def __init__(self, database_file, task_queue, send_queue, socket_to_uname_hash_map, hash_func):
        self.task_queue = task_queue
        self.request_dict = {LOG_NEW_USER : self.log_new_user, LOG_RETURNING_USER : self.log_returning_user}
        self.socket_to_uname_hash_map = socket_to_uname_hash_map
        connection = sqlite3.connect(database_file)
        self.crsr = connection.cursor()
        self.crsr.execute(CREATE_USER_TABLE)
        self.hash_func = hash_func
        self.send_queue = send_queue
        self.start()


    def start(self):
        while True:
            self.process_request(self.task_queue.get())


    def process_request(self, request_and_sock):
        request, sock = request_and_sock
        request_type, arguments = request.split('?')
        self.request_dict[request_type](sock, [equation.split('=')[1] for equation in arguments.split('&')])


    def log_new_user(self, sock, arguments):
        uname_hash = self.hash_func(arguments[0]).hexdigest()
        if not self.crsr.execute(SELECT('users', '*', str.format('username_hash = {}', uname_hash))):
            self.send_queue.put((USER_ALREADY_EXISTS, sock))
            return
        password_hash = self.hash_func(arguments[1]).hexdigest()
        self.crsr.execute(INSERT('users', str.format('{},{},{}', uname_hash, password_hash, arguments[2])))
        self.socket_to_uname_hash_map[uname_hash] = sock
        self.send_queue.put((AUTH_OKAY, sock))


    def log_returning_user(self, sock, arguments):
        uname_hash = self.hash_func(arguments[0]).hexdigest()
        if not self.crsr.execute(SELECT('users', 'password_hash', str.format('username_hash = {}', uname_hash))):
            self.send_queue.put((WRONG_PASSWORD, sock))
            return
        self.socket_to_uname_hash_map[uname_hash] = sock
        self.send_queue.put((AUTH_OKAY, sock))
