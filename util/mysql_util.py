import pymysql

class MysqlDB():
    def __init__(self, host, port, user, password, db):
        self.conn = pymysql.connect(
            host = host,
            user = user,
            port = int(port),
            passwd = password,
            db = db
        )
        self.cur = self.conn.cursor(cursor= pymysql.cursors.DictCursor)

    def __del__(self):
        self.cur.close()
        self.conn.close()

    def select_db(self, sql):
        self.conn.ping(reconnect=True)
        self.cur.execute(sql)
        data = self.cur.fetchall()
        return data

    def exec_db(self, sql):
        self.conn.ping(reconnect= True)
        try:
            self.cur.execute(sql)
            self.conn.commit()
            return True
        except Exception as e:
            self.conn.rollback()
            print('sql exec erorr: ', e)
            return False
