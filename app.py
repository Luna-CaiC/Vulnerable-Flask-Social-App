import sys, json, random, re, sqlite3, string
import xml.etree.ElementTree

try:
    from flask import Flask, request, render_template, render_template_string, session, redirect, url_for 
    app = Flask(__name__)
    app.secret_key = 'cs458558'
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    # Disable cache, friendly for test
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
except ImportError:
    app = None
    print("Please install 'flask' to run this vulnerable app")
    sys.exit(1)

connection = sqlite3.connect(":memory:", check_same_thread=False)
cursor = connection.cursor()
# Create users table
cursor.execute("""
    CREATE TABLE users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        name TEXT,
        password TEXT,
        description TEXT
    )
""")

USERS_XML = """<?xml version="1.0" encoding="utf-8"?>
<users>
<user id="0"><username>Alice</username><name>Alice</name><password>123456789</password></user>
<user id="1"><username>Bob</username><name>Bob</name><password>123</password></user>
<user id="2"><username>Charlie</username><name>Charlie</name><password>passwd</password></user>
<user id="3"><username>David</username><name>David</name><password>getin</password></user>
<user id="4"><username>Ella</username><name>Ella</name><password>secret</password></user>
</users>"""
VERSION = "v<b>0.1</b>"

tree = xml.etree.ElementTree.fromstring(USERS_XML)
for user in tree.findall("user"):
    username = user.findtext("username")
    name = user.findtext("name")
    password = user.findtext("password")
    description = "No bio yet"
    cursor.execute("""
        INSERT INTO users (username, name, password, description)
        VALUES (?, ?, ?, ?)
    """, (username, name, password, description))

# create session table
cursor.execute("""
    CREATE TABLE sessions(
        session_token TEXT,
        username TEXT
    )
""")
# create posts table
cursor.execute("""
    CREATE TABLE posts (
        post_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        body TEXT,
        comments TEXT,
        share TEXT CHECK(share IN ('yes', 'no')) DEFAULT 'no'
    )
""")
cursor.executemany("""
    INSERT INTO posts (username, body, comments, share)
    VALUES (?, ?, ?, ?)
""", [
    ("Alice", "Welcome to my first post!", json.dumps({}), "yes"),
    ("Bob", "This is a private post by Bob.", json.dumps({}), "yes"),
    ("Charlie", "Charlie here. Posting something interesting.", json.dumps({}), "yes"),
    ("Dennis", "I love low-level programming!", json.dumps({}), "no"),
    ("Ella", "Hola!", json.dumps({}), "no"),
])
connection.commit()
cursor.close()


@app.route('/')
def index():
    if not 'user' in session.keys():
        return redirect(url_for('login'))
    user = current_user()

    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    posts = []
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM posts WHERE share = 'yes';")
    for post in cursor:
        comments = json.loads(post[3]) if post[3] else {}
        posts.append({
            "post_id" : post[0],
            "username": "/"+post[1],
            "body": post[2],
            "comments": comments,
            "share": post[4],
        })

    cursor.close()
    posts.reverse()
    return render_template('index.html', user=user, posts=posts)


@app.route('/post', methods=['GET', 'POST'])
def post():
    if request.method != 'POST':
        return redirect(url_for('index'))

    if not request.form.get("posting"):
        return redirect(url_for('index'))

    post_content = request.form.get("posting")

    user = current_user()
    share = "yes"
    post_content = request.form.get("posting")

    private = request.form.get("private")
    if str(private) == 'on':
        share = "no"

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO posts (username, body, comments, share)
    VALUES (?, ?, ?, ?)
""", (user["username"], post_content, "", share))
    
    cursor.close()
    return redirect(url_for('index'))

@app.route("/postcomment/<int:post_id>", methods=["POST"])
def postcomment(post_id):
    comment_text = request.form.get("comment")
    user = current_user()["username"]

    cursor = connection.cursor()
    cursor.execute("SELECT comments FROM posts WHERE post_id=?", (post_id,))
    row = cursor.fetchone()

    if row:
        try:
            comments = json.loads(row[0]) if row[0] else {}
        except json.JSONDecodeError:
            comments = {}
        comments[user] = comment_text
        updated_comments = json.dumps(comments)
        cursor.execute("UPDATE posts SET comments=? WHERE post_id=?", (updated_comments, post_id))
        connection.commit()

    cursor.close()
    return redirect(url_for('index'))


@app.route('/search', methods=['POST'])
def search():
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    user = current_user()
    search = request.form.get("search")

    search = remove_and_or(search)

    query = "SELECT * FROM posts WHERE (body LIKE '%" + \
          search + "%' OR username LIKE '%" + search + "%') AND share = 'yes';"
    
    try:
        cursor = connection.cursor()
    except:
        return redirect(url_for('index'))

    try:
        cursor.execute(query)
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return redirect(url_for('index'))   

    results = []
    for post in cursor:
        comments = json.loads(post[3]) if post[3] else {}
        results.append({
            "post_id" : post[0],
            "username": "/"+post[1],
            "body": post[2],
            "comments": comments,
            "share": post[4],
        })

    cursor.close()
    
    f = open('templates/results.html')
    temp = f.read()
    f.close()
    temp = temp.replace('RESULTS', search)

    return render_template_string(temp, user=user, results=results)


# visit a user's page
@app.route('/u/<username>')
def user_page(username):
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    user = current_user()
    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    user_data = get_user(username)

    if user_data == None:
        return redirect(url_for('index'))
    else:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM posts WHERE username = '" +
                       username + "' and share = 'yes';")

        posts = []
        for post in cursor:
            comments = json.loads(post[3]) if post[3] else {}
            posts.append({
                "post_id" : post[0],
                "username": "/"+post[1],
                "body": post[2],
                "comments": comments,
                "share": post[4],
            })

        cursor.close()
        posts.reverse()
        return render_template('user.html', user=user_data, results=posts)


def generate_session_id(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    user = current_user()
    if user != {}:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM sessions WHERE username = '" +
                       user['username'] + "';")
        cursor.close()

    # Remove the session token from the user
    del session['user']

    return redirect(url_for('login'))


@app.route('/authenticate', methods=['POST', 'GET'])
def authenticate():
    username = request.form.get("username")
    password = request.form.get("password")
    username = remove_semicolon(username)
    password = remove_semicolon(password)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE username = '" +
                       username + "' and password = '" + password + "';")
    except:
        return redirect(url_for('login'))

    results = [{"username": username,
                "name": name,
                "password": password,
                "description": description,
                } for (id, username, name, password, description) in cursor]
    cursor.close()
    if len(results) > 0:
        # generate a random session token
        session_token = random.randint(0, 1000000)
        cursor = connection.cursor()
        cursor.execute("INSERT INTO sessions (session_token, username) VALUES ('" +
                       str(session_token) + "', '" + username + "');")

        cursor.close()
        session['user'] = session_token
        return redirect(url_for('index'))

    else:
        return redirect(url_for('login'))


@app.route('/settings')
def settings():
    if not 'user' in session.keys():
        return redirect(url_for('login'))

    user = current_user()
    return render_template('settings.html', user=user, success=None)


@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session.keys():
        return redirect(url_for('login'))

    fn = request.form.get("name")
    desc = request.form.get("description")

    fn = remove_select_insert(fn)
    desc = remove_select_insert(desc)

    user = current_user()
    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    cursor = connection.cursor()

    try:
        query = "UPDATE users SET name='" + fn + "', description='" + desc + "' WHERE username = '" + user["username"] + "';"
        cursor.execute(query)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return render_template('settings.html', user=user, success=False)

    cursor.close()

    user = current_user()

    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    return render_template('settings.html', user=user, success=True)


@app.route('/update_password', methods=['POST'])
def update_password():

    if 'user' not in session.keys():
        return redirect(url_for('login'))
    
    old_pw = request.form.get("old_password")
    new_pw = request.form.get("new_password")
    confirm_pw =  request.form.get("confirm_password")

    old_pw = remove_select_insert(old_pw)
    new_pw = remove_select_insert(new_pw)
    confirm_pw = remove_select_insert(confirm_pw)

    user = current_user()
    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    if(new_pw != confirm_pw):
        return render_template('settings.html', user=user, success=False)
    
    cursor = connection.cursor()
    query = "UPDATE users SET password = '" + new_pw + "' WHERE username = '" + user["username"] + "' AND password = '" + old_pw + "';"
    try:
        cursor.execute(query)
        if cursor.rowcount == 0:
            return render_template('settings.html', user=user, success=False)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return render_template('settings.html', user=user, success=False)

    cursor.close()
    user = current_user()

    if user == {}:
        del session['user']
        return redirect(url_for('index'))

    return render_template('settings.html', user=user, success=True)


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html'), 404


def remove_semicolon(value):
    return re.sub(r";", "", value)


def remove_and_or(value):
    value = remove_semicolon(value)
    value = re.sub(r"\bor\b", "", value, flags=re.IGNORECASE)
    value = re.sub(r"\band\b", "", value, flags=re.IGNORECASE)
    return value


def remove_select_insert(value):
    value = remove_and_or(value)
    value = re.sub(r"\bselect\b", "", value, flags=re.IGNORECASE)
    value = re.sub(r"\binsert\b", "", value, flags=re.IGNORECASE)
    return value


def current_user():
    if 'user' not in session.keys():
        return {}
    else:
        session_token = session['user']
        try:
            cursor = connection.cursor()
        except:
            return {}

        query = "SELECT username FROM sessions WHERE session_token = ?"
        cursor.execute(query, (session_token,))

        u = [x for x in cursor]
        try:
            cursor.execute("SELECT * FROM users WHERE username='" +
                           str(u[0][0]) + "';")
        except:
            return {}

        results = [{"username": username,
                    "name": name,
                    "description": description,
                    } for (id, username, name, password, description) in cursor]

        cursor.close()
        if len(results) > 0:
            return results[0]
        else:
            return {}


def get_user(username):

    cursor = connection.cursor()
    try:
        query = """SELECT * FROM users WHERE username = ?"""
        cursor.execute(query, (username,))
    except:
        return {}

    results = [{"username": username,
                "name": name,
                "description": description,
                } for (id, username, name, password, description) in cursor]

    cursor.close()

    if len(results) > 0:
        return results[0]
    else:
        return None


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
