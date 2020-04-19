import os
import re
import nltk
import spacy
import random
import sqlite3
import warnings
import emoji as emoji
from nltk import WordNetLemmatizer
from difflib import SequenceMatcher
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, request, session

user = ""
app = Flask(__name__)
mail = Mail(app)
if __name__ == '__main__':
    app.run()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/logos/'
app.secret_key = 'CAPEs secret key CAPEs'
app.config['SESSION_TYPE'] = 'null'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '2020capes@gmail.com'
app.config['MAIL_PASSWORD'] = 'Senoritas2020'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


# vendor home page
@app.route('/home', methods=["GET", "POST"])
def home():
    if session['logged_in'] == False:  return render_template('Login.html')
    if request.method == "POST":
        title = request.form['tit']
        return redirect(url_for('update', pe=title))
    user = session['username']
    con = sqlite3.connect('CAPEsDatabase.db')
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM certificate WHERE lower(v_username) ='" + user + "'")
        rows = cur.fetchall()
    return render_template('home.html', rows=rows)


# vendor list page
@app.route('/list', methods=["GET", "POST"])
def ViewListVendors():
    if session['logged_in'] == False:  return render_template('Login.html')
    user = session['username']
    conn = sqlite3.connect("CAPEsDatabase.db")
    cursor = conn.cursor()
    result = cursor.execute(" SELECT * FROM  vendor ")
    rows = result.fetchall()
    return render_template('beneficiary/vendor-list.html', c=rows)


# vendor details page
@app.route('/de/<v_username>', methods=["GET", "POST"])
def ViewVendorDetails(v_username):
    if session['logged_in'] == False:  return render_template('Login.html')
    user = session['username']
    conn = sqlite3.connect("CAPEsDatabase.db")
    cursor = conn.cursor()
    result = cursor.execute(" SELECT * FROM  vendor where v_username ='" + v_username + "'")
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM certificate WHERE lower(v_username) ='" + v_username + "'")
        rows = cur.fetchall()
    return render_template('beneficiary/vendor-details.html', c=result, users=v_username, user=user, rows=rows)


# Beneficiary  recommecndation page
@app.route('/recommendation')
def RecommendationPEs():
    if session['logged_in'] == False:  return render_template('Login.html')
    conn = sqlite3.connect("CAPEsDatabase.db")
    cursor = conn.cursor()
    cursor.execute(" SELECT * FROM result where b_id='" + session['username'] + "'")
    result = cursor.fetchall()
    return render_template('beneficiary/recommendation.html', rows=result)


# todo ?
# beneficiary home page
@app.route('/bhome')
def Bhome():
    if session['logged_in'] == False:  return render_template('Login.html')
    user = session['username']
    return render_template('beneficiary/home.html')


# vendor add PE page
@app.route("/add", methods=["GET", "POST"])
def add():
    if session['logged_in'] == False:  return render_template('Login.html')
    if request.method == "POST":
        title = request.form['title']
        v_username = session['username']
        major =request.form.get('major')
        level = request.form.get('level')
        field = request.form['field']
        pre_req = request.form['pre_req']
        pre_c = request.form['pre_c']
        prog_l = request.form['prog_l']
        duration = request.form.get('duration')
        exam_name = request.form['exam']
        description = request.form['description']
        URLlink = request.form['URLlink']

        conn = sqlite3.connect("CAPEsDatabase.db")
        cursor = conn.cursor()
        cursor.execute('INSERT INTO certificate VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', (
            None, title, v_username, major, level, field, pre_req, pre_c, prog_l, duration, description, exam_name,
            URLlink))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('home'))
    return render_template("vendor/add.html")


# vendor update PE page
@app.route('/update/<pe>', methods=['GET', 'POST'])
def update(pe):
    if session['logged_in'] == False: return render_template('Login.html')
    if request.method == "GET":
        conn = sqlite3.connect("CAPEsDatabase.db")
        cursor = conn.cursor()
        result = cursor.execute(" SELECT * FROM  certificate where p_id='" + pe + "'")
        return render_template('vendor/update.html', info=result)
    if request.method == "POST":
        title = request.form['title']
        v_username = session['username']
        major = request.form.get('major')
        level = request.form.get('level')
        field = request.form['field']
        pre_req = request.form['pre_req']
        pre_c = request.form['pre_c']
        prog_l = request.form['prog_l']
        duration = request.form.get('duration')
        exam_name = request.form['exam']
        description = request.form['description']
        URLlink = request.form['URLlink']

        conn = sqlite3.connect("CAPEsDatabase.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE certificate SET name='" + title +
                       "', major='" + major +
                       "', level='" + level +
                       "', field='" + field +
                       "', pre_req='" + pre_req +
                       "', pre_c='" + pre_c +
                       "', prog_l='" + prog_l +
                       "', duration='" + duration +
                       "', description='" + description +
                       "', exams='" + exam_name +
                       "', URLlink='" + URLlink +
                       "' WHERE  p_id='" + pe + "';")
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('home'))
    return render_template("vendor/update.html")


# delete vendor info page
@app.route('/delete/<pe>', methods=['GET', 'POST'])
def delete(pe):
    if session['logged_in'] == False: return render_template('Login.html')
    user = session['username']
    conn = sqlite3.connect("CAPEsDatabase.db")
    cursor = conn.cursor()
    cursor.execute('DELETE FROM certificate WHERE p_id=?', (pe,))
    conn.commit()
    return redirect(url_for('home'))


# upload vendor info page
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    # Check if a valid image file was uploaded
    if request.method == 'POST':
        print("hi rnrn")

        if 'img' not in request.files:
            print("hi leen")
            return redirect(request.url)
        file = request.files['img']
        print("hi lnrn")
        if file.filename == '':
            print("hello")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            print("hi")
            # The image file seems valid!
            # Get the filenames and pass copy in logo dir and keep it in database
            name = request.form['username']
            password = request.form['password']
            desc = request.form['descption']
            email = request.form['email']
            conn = sqlite3.connect("CAPEsDatabase.db")
            cursor = conn.cursor()
            cursor.execute('INSERT INTO vendor VALUES (?,?,?,?,?)', (name, password, desc, email, file.filename))
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            conn.commit()
            cursor.close()
            conn.close()
        return render_template('upload.html')
    # If no valid image file was uploaded, show the file upload form:
    return render_template('upload.html', error="Not added")


# method for upload vendor image
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# reset password page
@app.route('/resetpassword')
def resetpassword():
    return render_template('resetpassword.html')


# login page
@app.route('/', methods=['GET', 'POST'])
def Login():
    session['logged_in'] = False
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        completion = b_validate(username, password)
        if completion == False:
            completion = v_validate(username, password)
            if completion == False:
                error = 'Invalid Credentials. Please try again.'
            else:
                session['logged_in'] = True
                return redirect(url_for('home'))
        else:
            session['logged_in'] = True
            return redirect(url_for('Bhome'))
    if 'forgetpass' in session:
        error2 = session['forgetpass']
    else:
        error2 = None
    return render_template('Login.html', error=error, error2=error2)


# method for beneficiary login
def b_validate(username, password):
    print(username)
    print(password)
    con = sqlite3.connect('CAPEsDatabase.db')
    completion = False
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM beneficiary")
        rows = cur.fetchall()
        for row in rows:
            dbUser = row[0]
            dbPass = row[1]
            print(dbUser)
            print(dbPass)
            if ((dbUser == username) and (dbPass == password)):
                session['username'] = dbUser
                completion = True
    return completion


# method for vendor login
def v_validate(username, password):
    con = sqlite3.connect('CAPEsDatabase.db')
    completion = False
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM vendor")
        rows = cur.fetchall()
        for row in rows:
            dbUser = row[0]
            dbPass = row[1]
            if dbUser == username and dbPass == password:
                session['username'] = dbUser
                completion = True
    return completion


# logout
@app.route('/logout')
def logout():
    return redirect(url_for('Login'))


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    error = None
    if request.method == 'POST':
        token = request.form['Token']
        password = request.form['password']
        ConfirmPassword = request.form['ConfirmPassword']
        con = sqlite3.connect('CAPEsDatabase.db')
        cur = con.cursor()
        with con:
            cur.execute("SELECT * FROM ResetPassword")
            rows = cur.fetchall()
            for row in rows:
                Token = row[1]
                username = row[0]
                if token == Token and username == session['username']:
                    if password == ConfirmPassword:
                        if session['table'] == 'vendor':
                            cur.execute(" UPDATE vendor SET password ='" + password + "' Where v_username='" + session[
                                'username'] + "'")
                            cur.execute('DELETE FROM ResetPassword WHERE username=?', (session['username'],))
                            con.commit()
                            return redirect(url_for('Login'))
                        elif session['table'] == 'beneficiary':
                            cur.execute(
                                " UPDATE beneficiary SET password ='" + password + "' Where b_username='" + session[
                                    'username'] + "'")
                            cur.execute('DELETE FROM ResetPassword WHERE username=?', (session['username'],))
                            con.commit()
                            return redirect(url_for('Login'))
                        else:
                            con.commit()
                    else:
                        error = "Password and Confirm Password fields not matching"
                        return render_template('resetpassword.html', error=error)
                else:
                    error = "Please enter a valid token"
                    return render_template('resetpassword.html', error=error)
    return render_template('resetpassword.html', error=error)


# method for vendor login
def E_validate(Email):
    completion = False
    con = sqlite3.connect('CAPEsDatabase.db')
    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM vendor")
        rows = cur.fetchall()
        for row in rows:
            email = row[3]
            if email.lower() == Email.lower():
                completion = True
                con.commit()
                session['table'] = 'vendor'
                return (completion, row[0])
            else:
                with con:
                    cur.execute("SELECT * FROM beneficiary")
                    rows = cur.fetchall()
                    for row in rows:
                        email = row[3]
                        if email.lower() == Email.lower():
                            completion = True
                            con.commit()
                            session['table'] = 'beneficiary'
                            return (completion, row[0])
    if completion == False:
        return (completion, None)


def sendmassage(token, email):
    msg = Message('Reset Password', sender='2020capes@gmail.com', recipients=[email])
    msg.body = "Hello \nDear user use this token to reset your password : " + token
    mail.send(msg)
    return None


def get_random_string(length=5, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    return ''.join(random.choice(allowed_chars) for i in range(length))


@app.route('/forgot', methods=['GET', 'POST'])
def ForgotPassword():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        completion, username = E_validate(email)
        if completion == False:
            error = 'Invalid Credentials. Please try again.'
            return render_template('forgetpassword.html', error=error)
        elif completion == True and username is not None:
            token = get_random_string()
            con = sqlite3.connect('CAPEsDatabase.db')
            cur = con.cursor()
            cur.execute('INSERT INTO ResetPassword VALUES (?,?)', (username, token))
            con.commit()
            cur.close()
            con.close()
            sendmassage(token, email)
            session['username'] = username
            return redirect(url_for('reset'))
    if request.method == 'GET':
        return render_template('forgetpassword.html', error=error)



# ________________________

# TODO: chat
nlp = spacy.load("en_core_web_md")
warnings.simplefilter("error", UserWarning)
connection = sqlite3.connect('CAPEsDatabase.db', check_same_thread=False)
cursor = connection.cursor()


def randomID():
    cursor.execute("SELECT qNumer FROM log")
    result = [i[0] for i in cursor.fetchall()]
    i = random.randint(0, 10000)
    if i not in result:
        return i
    else:
        return randomID()


# todo remove comment
wave_emoji = emoji.emojize(':wave:', use_aliases=True)
smile_emoji = emoji.emojize(':smile:', use_aliases=True)
thumbs_emoji = emoji.emojize(':thumbs_up:', use_aliases=True)
grimacing_emoji = emoji.emojize(':grimacing:', use_aliases=True)


def getinput(input):
    session['inpput'] = input.lower()


def setinput():
    res = session['res']
    # todo print
    print('res from set input', res)
    return res


# TODO remove comment
non_value = ['no', 'neither', 'not', 'non', 'all', 'every', 'dont', 'both', 'any', 'each', 'nothing', 'nor']
random_id = randomID()


def getQuestion():
    # question_result = session['question_result']
    cursor.execute("SELECT question FROM questions")
    session['question_result'] = [i[0] for i in cursor.fetchall()]
    # todo print
    print('question_result', session['question_result'])


# todo didnot check
def exitProgram(x, quz):
    res = session['res']
    exit_flag = session['exit_flag']
    if x == 'q':
        session['res'] = "Conversation ends. Bye!" + wave_emoji + "</br> </br> If you want to try again reload this page <3"
        data_ca = (
            quz, x, user, 'stopped',
            "Conversation ends. Bye!" + wave_emoji)
        uploadCA(data_ca)
        session['exit_flag'] = True

    elif x == 'f':
        session['res'] += " </br>Thank you for using CAPEs, Best wishes!" + smile_emoji + \
               "</br></br>Please, help us to improve CAPEs by completing this survey: " \
               "<a href=\"https://forms.gle/PCjbY7Znetn8xNQA9\">here</a>"
        data_ca = (quz, x, user, 'complete', "Thank you for using CAPEs, Best wishes!" + smile_emoji)
        uploadCA(data_ca)
        session['exit_flag'] = True


def getPattern(query):
    training_pattern = session['training_pattern']
    training_pattern.clear()
    print('qury', query)
    cursor.execute("SELECT anwser_p FROM pattern Where id_r = ?", [query])
    patterns = cursor.fetchall()
    for row in patterns:
        training_pattern.append(row[0])
    # todo print
    print('training_pattern Lok', training_pattern)
    return training_pattern


# todo didnot check
def removeKeyword(user_input):
    list_matching = session['list_matching']
    # todo print
    print('lis match', list_matching)
    keys = ' '.join(list_matching).split()
    removed_keyword = ' '.join(word for word in user_input.split() if word not in keys)
    return removed_keyword


def getKeyword(user_input, query):
    list_matching = session['list_matching']
    list_matching.clear()
    training_keyword = session['training_keyword']
    training_keyword.clear()
    cursor.execute("SELECT keyword FROM keyword Where id_r = ?", [query])
    keyword = cursor.fetchall()
    # todo print
    print('usr input', user_input)
    print('keyword', keyword)
    for row in keyword:
        training_keyword.append(row[0])
        match = SequenceMatcher(None, user_input, row[0]).find_longest_match(0, len(user_input), 0, len(row[0]))
        list_matching.append(row[0][match.b: match.b + match.size])
        list_matching = list(set(list_matching).intersection(set(training_keyword)))
        session['list_matching'] = list(set(list_matching).intersection(set(training_keyword)))
    # todo print
    print("keyword_tri", training_keyword)
    print('list_matching', list_matching)


# todo didnot check
def removeSpecialCharacters(user_input):
    patterns = r'[^a-zA-z0-9 #+\s]'
    user_input_removed_char = re.sub(patterns, '', user_input)
    return user_input_removed_char


# todo didnot check
def lemmatize(user_input):
    lemmatizer = WordNetLemmatizer()
    user_input_lemmatized = ' '.join(lemmatizer.lemmatize(w) for w in nltk.word_tokenize(user_input))
    return user_input_lemmatized


def generalKeyword(user_input, query):
    list_matching = session['list_matching']
    list_matching.clear()
    training_keyword = session['training_keyword']
    training_keyword.clear()
    cursor.execute("SELECT keyword FROM keyword Where id_c = ?", [query])
    result = cursor.fetchall()
    #todo print
    print('_____genKey___',result)
    for row in result:
        training_keyword.append(row[0])
        match = SequenceMatcher(None, user_input, row[0]).find_longest_match(0, len(user_input), 0, len(row[0]))
        list_matching.append(row[0][match.b: match.b + match.size])
        list_matching = list(set(list_matching).intersection(set(training_keyword)))
        session['list_matching'] = list(set(list_matching).intersection(set(training_keyword)))
    #todo print
    print('lost in gkey', session['list_matching'])


def patternSimilarity(user_input):
    training_pattern = session['training_pattern']
    # todo print
    print('form sim_pattern training_pattern', training_pattern)
    user = removeKeyword(user_input)
    user_cleaned = removeSpecialCharacters(user)
    # todo print
    print('user_cleaned', user_cleaned)
    similarity_list = []
    if len(user_cleaned) > 0:
        user_input_cleaned = lemmatize(user_cleaned)
        token1 = nlp(user_input_cleaned)
        for row in training_pattern:
            token2 = nlp(row)
            try:
                similarity = token1.similarity(token2)
            except UserWarning:
                similarity = 0.0
            similarity_list.append(similarity)
        return max(similarity_list)
    else:
        return 1


def rudeKeyword(user_input, count):
    rude_counter = session['rude_counter']
    res = session['res']
    rude_flag = session['rude_flag']
    temp = session['temp']
    reapet = session['reapet']
    res_rude = session['res_rude']
    questionN = session['questionN']
    list_matching = session['list_matching']
    question_result = session['question_result']
    session['list_matching'] = [ ]
    session['reapet'] = False
    #todo print
    print('---------------rude-----------------------')
    print('rude count', session['rude_counter'])
    print('questionN', questionN)
    print('listM', session['list_matching'])

    generalKeyword(user_input, 4)
    rude = session['list_matching']
    #todo print
    print('listM after', session['list_matching'])
    for word in session['list_matching']:
        if user_input._contains_(word):
            #todo print
            print('enter thier is rude')
            if session['rude_counter'] < 2:
                temp = questionN
                resp = 'This a warning for using a rude word!<br><br>'
                session['reapet'] = True
                session['res_rude'] = resp
                session['rude_counter'] += 1
                data_ca = (question_result[count], user_input, session['username'], 'continue', resp)
                uploadCA(data_ca)
            else:
                session['rude_flag'] = True
                session['res'] = 'You were warned for using rude words two times the program will terminate now.'
                data_ca = (question_result[count], user_input, session['username'], 'stopped',
                           'You were warned for using rude words two times the program will terminate now.')
                uploadCA(data_ca)


def response(word_type, id_g, count, user_input):
    res = session['res']
    question_result = session['question_result']
    temp = session['temp']
    questionN = session['questionN']
    temp = session['questionN']
    i_val = random.choice([0, 1])
    cursor.execute("SELECT ans2 FROM response Where id_c = ?", [id_g])
    result = cursor.fetchall()
    if id_g == 2:
        if word_type._contains('result') | word_type.contains_('record'):
            session['res'] = result[0][0] + "<br /><br /> Now," + temp
            data_ca = (question_result[count], user_input, user, 'continue', result[0][0])
            uploadCA(data_ca)
        else:
            session['res'] = result[1][0] + "<br /><br /> Now, " + temp
            data_ca = (question_result[count], user_input, user, 'continue', result[0][0])
            uploadCA(data_ca)
    else:
        resp = result[i_val][0]
        session['res'] = resp + "<br /><br /> Now, " + temp
        data_ca = (question_result[count], user_input, user, 'continue', str(resp))
        uploadCA(data_ca)


def checkGeneralKeyword(user_input, count):
    temp = session['temp']
    counter_q = session['counter_q']
    res = session['res']
    list_matching = session['list_matching']
    question_result = session['question_result']
    questionN = session['questionN']
    temp = questionN
    generalKeyword(user_input, 2)
    general = session['list_matching']
    print('list mtach vluae in gen:', session['list_matching'], len(session['list_matching']))
    if len(general) != 0:
        #todo print
        print('________________enter gen_______________')

        pattern_similarity = patternSimilarity(user_input)
        if pattern_similarity > 0.7:
            response(general, 2, count, user_input)
    else:
        #todo print
        print('________________enter weth_______________')

        generalKeyword(user_input, 3)
        #todo print
        print('wether',session['list_matching'])
        weather = session['list_matching']
        if len(weather) != 0:
            #todo print
            print('________________enter weth2_______________')
            pattern_similarity = patternSimilarity(user_input)
            if pattern_similarity > 0.65:
                response(weather, 3, count, user_input)
        else:
            #todo print
            print('________________enter soory_______________')

            session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
            data_ca = (question_result[count], user_input, user, 'continue',
                       "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
            uploadCA(data_ca)


def question():
    counter = session['counter']
    res = session['res']
    inpput = session['inpput']
    counter_q = session['counter_q']
    questionN = session['questionN']
    exit_flag = session['exit_flag']
    reapet = session['reapet']
    res_rude = session['res_rude']
    rude_flag = session['rude_flag']
    list_matching = session['list_matching']
    question_result = session['question_result']
    # question_result = questionN
    if counter > 5:  # TODO what will happen? ans: will delete
        """findCertificate()"""
        # exitProgram('f', '')
        # if we have time need to improve
    else:
        questions_joint = session['questionN']
        user_input = inpput
        # todo print
        print('qus', questions_joint)
        print('use input', user_input)
        user_input = removeSpecialCharacters(user_input)
        exitProgram(user_input, questions_joint)
        if not session['exit_flag']:
            rudeKeyword(user_input, session['counter'])  # rude word
            if session['reapet']:
                session['res'] = session['res_rude'] + session['questionN']
            else:
                if not session['rude_flag']:
                    # todo print
                    print('count+1', counter + 1)
                    getPattern(counter + 1)
                    getKeyword(user_input, counter + 1)
                    if len(session['list_matching']) != 0:
                        pattern_similarity = patternSimilarity(user_input)
                        # todo print
                        print("pattern_similarity", pattern_similarity)
                        if pattern_similarity > 0.7:
                            # todo list mathc for key
                            print('list mathc for key_________', session['list_matching'])
                            keyword = ','.join(session['list_matching'])
                            user_input_removed_keywords = "".join(removeKeyword(user_input))
                            for word in non_value:  # check none values
                                if user_input._contains_(word):
                                    keyword = "%"
                            data = (
                                random_id, user_input, user_input_removed_keywords, keyword, pattern_similarity,
                                questions_joint)
                            uploadLog(data)
                            if counter == 5:
                                responss = 'pre-cretificat q'
                            else:
                                responss = question_result[counter + 1]

                            data_ca = (questions_joint, user_input, user, 'continue', responss)
                            uploadCA(data_ca)
                            if counter <= 4:
                                questions_joint = ''.join(question_result[counter_q])  # loop over questions_joint table, and save the result in questions_joint
                                # todo print
                                session['questionN'] = questions_joint
                                session['res'] = questions_joint
                                # todo print
                                print('questionN', questionN)
                                print('res', session['res'])
                            elif counter == 5:
                                # findCertificate()
                                session['res'] = findCertificate()
                            # todo print
                            session['counter'] += 1
                            print('counter', counter)
                            session['counter_q'] += 1
                            print('counterq', counter_q)
                        else:
                            checkGeneralKeyword(user_input, counter)
                    else:
                        checkGeneralKeyword(user_input, counter)


def uploadLog(data):
    cursor.execute(
        "INSERT INTO log (qNumer, userAns, textWithOutKey, keywords , patternAsimilarity, question) "
        "VALUES (?, ?, ?, ?, ?, ?)", data)
    connection.commit()


def print_result(accepted_list, result, w):
    res = session['res']
    inpput = session['inpput']
    certificate = session['certificate']
    vendor = session['vendor']
    exam = session['exam']
    link = session['link']
    #todo print
    print('acented inlast', accepted_list)
    print('result in last', result)
    if accepted_list._len_() != 0:
        session['res'] = "I found the most matching certificate for you: </br></br>"
        count = 1
        for row in result:
            if row[2] in accepted_list:
                certificate = row[0]
                vendor = row[1]
                exam = row[3]
                link = row[4]
                session['res'] += str(count) + "- " + certificate + ".</br></br>"
                data = (user, certificate, vendor, exam, link)
                uploadResult(data)
                count += 1
            else:
                continue
        session['res'] += 'If you want more information you can go to <b>Recommendation</b>tab</br>'
    else:
        # print("Sorry, I can not found the most matching certificate for you")
        session['res'] = 'Sorry, I could not found the most matching certificate for you' + grimacing_emoji
    exitProgram('f', '')


def q7_check_ans(uniq):
    q_count = session['q_count']
    #todo print
    print('q_count in q7' , q_count)
    print('uniq in q7', uniq)
    accepted_c = session['accepted_c']
    inpput = session['inpput']
    res = session['res']
    ans = inpput
    data_ca = (res, ans, user, 'continue', 'after those question the result will show')
    uploadCA(data_ca)
    while q_count >= 0:
        if ans._contains_(str(q_count)):
            try:
                session['accepted_c'].append(uniq[q_count])
            except IndexError:
                pass
        else:
            'noting'
        q_count -= 1
        session['q_count'] -= 1
    #todo print
    print('accepted ones', session['accepted_c'])


def findCertificate():
    res = session['res']
    inpput = session['inpput']
    q_count = session['q_count']
    result_preC = session['result_preC']
    uniq = session['uniq']
    accepted_c = session['accepted_c']
    count_q7 = session['count_q7']
    w = random_id
    # w = 9502

    cursor.execute("SELECT  keywords FROM log WHERE qNumer=?", [w])
    result = cursor.fetchall()
    # todo print
    print('result',result)
    a = []
    for k in range(1):
        a.append([])
        for j in range(6):
            a[k].append([])
            values = str(result[j][0]).split(",")
            for v in values:
                # print(result[k][i])
                a[k][j].append(v)
    # for access a q1
    # print(a[0][0])
    major = []
    len_m = len(a[0][0])
    for x in range(0, 3):
        if len_m > 0:
            if a[0][0][x]._contains_('computer science'):
                major.append('%cs%')
            elif a[0][0][x]._contains_('computer information system'):
                major.append('%cis%')
            elif a[0][0][x]._contains_('cyber security'):
                major.append('%cys%')
            elif a[0][0][x]._contains_('artificial intelligent'):
                major.append('%ai%')
            elif a[0][0][x]._contains_('%'):
                major.append('%')
            else:
                major.append('%' + a[0][0][x] + '%')
        elif len_m <= 0:
            major.append('')
        len_m -= 1
    # ___________________________
    level = []
    len_l = len(a[0][1])
    max = 0
    asnum = 0
    for x in range(0, 3):
        if len_l > 0:
            if a[0][1][x] in "one":
                asnum = 1
            elif a[0][1][x] in "two":
                asnum = 2
            elif a[0][1][x] in "three":
                asnum = 3
            elif a[0][1][x] in "four":
                asnum = int(4)
            elif a[0][1][x] in "five":
                asnum = int(5)
            elif a[0][1][x] in "six":
                asnum = int(6)
            elif a[0][1][x] in "seven":
                asnum = int(7)
            elif a[0][1][x] in "eight":
                asnum = int(8)
            elif a[0][1][x] in "nine":
                asnum = int(9)
            elif a[0][1][x] in "ten":
                asnum = int(10)
            elif a[0][1][x] in "%":
                asnum = int(10)
            else:
                asnum = int(a[0][1][x])
        if asnum > max:
            max = asnum
        level.append(max)
        len_l -= 1
    # __________________________
    filed = []
    len_f = len(a[0][2])
    for x in range(0, 3):
        if len_f > 0:

            if a[0][2][x] in "oop":
                filed.append("%java%")
            elif a[0][2][x] in "artificial intelligence":
                filed.append("%ai%")
            elif a[0][2][x] in "machine learning":
                filed.append("%ml%")
            elif a[0][2][x] in "%":
                filed.append("%")
            else:
                filed.append('%' + a[0][2][x] + '%')
        elif len_f <= 0:
            filed.append('')
        len_f -= 1
    # ___________________________
    program_language = []
    len_p = len(a[0][3])
    for x in range(0, 3):
        if len_p > 0:
            if a[0][3][x] in "HTML5":
                program_language.append("%HTML%")
            elif a[0][3][x] in "CSS3":
                program_language.append("%CSS%")
            elif a[0][3][x] in "%":
                program_language.append("%")
            else:
                program_language.append('%' + a[0][3][x] + '%')

        elif len_p <= 0:
            program_language.append('')
        len_p -= 1
    # ________________________
    vendor_name = []
    len_v = len(a[0][4])
    for x in range(0, 3):
        if len_v > 0:
            if a[0][4][x] in "python":
                vendor_name.append("%python institute%")
            elif a[0][4][x] in "red hat":
                vendor_name.append("%red hat academy%")
            elif a[0][4][x] in "%":  # chage it
                vendor_name.append("%")
            else:
                vendor_name.append('%' + a[0][4][x] + '%')
        elif len_v <= 0:
            vendor_name.append('')
        len_v -= 1
    # ________________________
    duration = []
    len_d = len(a[0][5])
    for x in range(0, 3):
        if len_d > 0:
            if a[0][5][x] in "%":
                duration.append("%")
            else:
                duration.append('%' + a[0][5][x] + '%')
        elif len_d <= 0:
            duration.append('')
        len_d -= 1

    cursor.execute(
        "SELECT name , v_username , pre_c , exams , urllink FROM certificate WHERE (major like ? or major like ? or major like ?)and (level <= ?) and (field like ? or field like ? or field like ? ) and (prog_l like ? or prog_l like 'null' or prog_l like ? or prog_l like ?)and (v_username like ? or v_username like ? or v_username like ?) and (duration like ? or duration like ? or duration like ?)",
        (major[0], major[1], major[2], level[0], filed[0], filed[1], filed[2],
         program_language[0],
         program_language[1], program_language[2], vendor_name[0], vendor_name[1], vendor_name[2], duration[0],
         duration[1], duration[2]))
    session['result_preC'] = cursor.fetchall()
    #todo print
    print('result afterfilter', session['result_preC'])
    seen = set()
    uniq = []
    # print('result: ',result_preC)
    # to take the duplicate pre-certificate
    for x in session['result_preC']:
        if x[2] not in seen:
            session['uniq'].append(x[2])
            seen.add(x[2])

    session['count_q7'] = session['uniq']._len_()
    # todo print
    print('uniq', session['uniq'])
    print('uniq num', session['count_q7'])
    print('q_count', session['q_count'])
    # print('uniq:',uniq)
    qusion7 = ' '
    for row in session['uniq']:
        if row != 'NULL':
            # q7 = "Have you taken this pre-certificate", row, "? (yes or no)"
            qusion7 += str(session['q_count']) + '-' + row + '</br>'
        if row == 'NULL':
            session['accepted_c'].append(row)
        session['q_count'] = session['q_count'] + 1
        session['count_q7'] = session['count_q7'] - 1
    #todo print
    print('q_count after', session['q_count'])
    print('count_7', session['count_q7'])
    # print(qusion7)
    if qusion7.strip():
        q7 = 'Do you have any certificates from this list?</br>' + qusion7 + 'Please enter all <b>numbers</b> for certificates you have.'
    else:
        # todo please change it.
        q7 = 'Are you ready to see the result.'

    return q7


def uploadResult(data):
    cursor.execute("INSERT INTO result (b_id, certificate, vendor, exam, link) VALUES (?, ?, ?, ?, ?)", data)
    connection.commit()


def uploadCA(data):
    cursor.execute("INSERT INTO CA (question, answer, b_id, complete_chat, response) VALUES (?, ?, ?, ?,?)", data)
    # cursor.execute("INSERT INTO CA (question, answer, b_id, complete_chat, response) VALUES (?, ?, ?, ?,?)", data)
    connection.commit()


# ______________________

@app.route('/get')
def get_bot_response():
    res = session['res']
    counter = session['counter']
    uniq = session['uniq']
    result_preC = session['result_preC']
    accepted_c = session['accepted_c']

    userText = request.args.get('msg')
    getinput(userText)
    getQuestion()

    if counter < 6:
        question()
    elif counter == 6:
        q7_check_ans(session['uniq'])
        session['counter'] += 1
        print_result(session['accepted_c'], session['result_preC'], random_id)
    elif counter > 6:
        session['res'] = 'If you want to try again reload this page <3'

    x = setinput()

    return str(x)