from flask import Flask, render_template, redirect, url_for, request, session
from werkzeug.utils import secure_filename
import sqlite3
import os
import re
import nltk
import spacy
import warnings
from nltk import WordNetLemmatizer
from difflib import SequenceMatcher
from flask_mail import Mail, Message
import random

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
@app.route('/list')
def ViewListVendors():
    if session['logged_in'] == False:  return render_template('Login.html')
    global user
    user = session['username']
    conn = sqlite3.connect("CAPEsDatabase.db")
    cursor = conn.cursor()
    result = cursor.execute(" SELECT * FROM  vendor ")
    rows = result.fetchall()
    return render_template('beneficiary/vendor-list.html', c=rows, user=user)


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
# @app.route('/', methods=["GET", "POST"])
def Bhome():
    if session['logged_in'] == False:  return render_template('Login.html')
    user = session['username']
    #conn = sqlite3.connect("CAPEsDatabase.db")
    #cursor = conn.cursor()
    #cursor.execute(" SELECT * FROM  vendor")
    #result = cursor.fetchall()
    # ,user=user
    #return render_template('beneficiary/home.html', rows=result, i=0)
    return render_template('beneficiary/home.html')


# vendor add PE page
@app.route("/add", methods=["GET", "POST"])
def add():
    if session['logged_in'] == False:  return render_template('Login.html')
    if request.method == "POST":
        title = request.form['title']
        v_username = session['username']
        major = request.form['major']
        level = request.form['level']
        field = request.form['field']
        pre_req = request.form['pre_req']
        pre_c = request.form['pre_c']
        prog_l = request.form['prog_l']
        duration = request.form['duration']
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
        major = request.form['major']
        level = request.form['level']
        field = request.form['field']
        pre_req = request.form['pre_req']
        pre_c = request.form['pre_c']
        prog_l = request.form['prog_l']
        duration = request.form['duration']
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


## delete vendor info page
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
                global user
                user = session['username']
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
                        error = "Password and Confirm Password fileds not matching"
                        return render_template('resetpassword.html', error=error)
                else:
                    error = "Please enter a right token"
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
            if email == Email:
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
                        if email == Email:
                            completion = True
                            con.commit()
                            session['table'] = 'beneficiary'
                            return (completion, row[0])
    if completion == False:
        return (completion, None)


def sendmassage(token, email):
    msg = Message('Reset Password', sender='2020capes@gmail.com', recipients=[email])
    msg.body = "Hello \n Dear user use this token to reset your password : " + token
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
            """
            sendmassage(token,email)"""
            session['username'] = username
            return redirect(url_for('reset'))
    if request.method == 'GET':
        return render_template('forgetpassword.html', error=error)


# _______________________________________________________________________________________

nlp = spacy.load("en_core_web_lg")
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


exam = []
link = []
vendor = []
certificate = []
list_matching = []
question_result = []
training_pattern = []
training_keyword = []
counter = 0
rude_counter = 0
res = ''
inpput = ''
count_q7 = 1
counter_q = 1
rude_flag = False
questionN = 'What is your major?'
temp = ' '
exit_flag = False
reapet = False
res_rude = ' '
accepted_c = []
q_count = 0
result_preC = []
uniq = []


def getinput(input):
    global inpput
    inpput = input


def setinput():
    global res
    return res


# TODO remove comment
non_value = ['no', 'neither', 'not', 'non', 'all', 'every', 'dont', 'both', 'any', 'each', 'nothing', 'nor']
random_id = randomID()


def getQuestion():
    global question_result
    cursor.execute("SELECT question FROM questions")
    question_result = [i[0] for i in cursor.fetchall()]
    # question_result.append('pre-certificate')


def exitProgram(x, question):
    global res
    global exit_flag
    if x == 'q':
        # TODO remove comment
        # print("CAPES: Conversation ends. Your records are saved in logs. Bye!wave_emoji")
        res = "Conversation ends.Bye!wave_emoji" + "</br> </br> If you want to try again reload this page <3"
        data_ca = (
            question, x, user, 'stopped',
            "Conversation ends. Bye!wave_emoji")
        uploadCA(data_ca)
        exit_flag = True

    elif x == 'f':
        # TODO remove comment
        # print("CAPES: Thank you for using CAPEs, Best wishes! smile_emoji")
        res += " </br>Thank you for using CAPEs, Best wishes! smile_emoji" + "</br></br> please help us to improve CAPEs " \
                                                                             "by fill this survey. <a href=\"https://forms.gle/PCjbY7Znetn8xNQA9\">here</a>"
        data_ca = (question, x, user, 'complete', "Thank you for using CAPEs, Best wishes! smile_emoji")
        uploadCA(data_ca)
        exit_flag = True


def getPattern(query):
    cursor.execute("SELECT anwser_p FROM pattern Where id_r = ?", [query])
    patterns = cursor.fetchall()
    for row in patterns:
        training_pattern.append(row[0])
    return training_pattern


def removeKeyword(user_input):
    keys = ' '.join(list_matching).split()
    removed_keyword = ' '.join(word for word in user_input.split() if word not in keys)
    return removed_keyword


def getKeyword(user_input, query):
    global list_matching
    list_matching.clear()
    cursor.execute("SELECT keyword FROM keyword Where id_r = ?", [query])
    keyword = cursor.fetchall()
    for row in keyword:
        training_keyword.append(row[0])
        match = SequenceMatcher(None, user_input, row[0]).find_longest_match(0, len(user_input), 0, len(row[0]))
        list_matching.append(row[0][match.b: match.b + match.size])
        list_matching = list(set(list_matching).intersection(set(training_keyword)))


def removeSpecialCharacters(user_input):
    patterns = r'[^a-zA-z0-9 #+\s]'
    user_input_removed_char = re.sub(patterns, '', user_input)
    return user_input_removed_char


def lemmatize(user_input):
    lemmatizer = WordNetLemmatizer()
    user_input_lemmatized = ' '.join(lemmatizer.lemmatize(w) for w in nltk.word_tokenize(user_input))
    return user_input_lemmatized


def generalKeyword(user_input, query):
    training_keyword.clear()
    global list_matching
    list_matching.clear()
    cursor.execute("SELECT keyword FROM keyword Where id_c = ?", [query])
    result = cursor.fetchall()
    for row in result:
        training_keyword.append(row[0])
        match = SequenceMatcher(None, user_input, row[0]).find_longest_match(0, len(user_input), 0, len(row[0]))
        list_matching.append(row[0][match.b: match.b + match.size])
        list_matching = list(set(list_matching).intersection(set(training_keyword)))


def patternSimilarity(user_input):
    user = removeKeyword(user_input)
    user_cleaned = removeSpecialCharacters(user)
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
    global rude_counter
    global res
    global rude_flag
    global temp
    global reapet
    global res_rude
    reapet = False
    generalKeyword(user_input, 4)
    rude = list_matching
    for word in rude:
        if user_input.__contains__(word):
            # res = rude_counter
            # print(rude_counter)
            if rude_counter < 2:
                temp = questionN
                resp = 'This a warning for using rude word! <br /><br />'
                # print(resp)
                reapet = True
                res_rude = resp
                # print('after:', rude_counter)
                rude_counter += 1
                # print(rude_counter)
                data_ca = (question_result[count], user_input, session['username'], 'continue', resp)
                uploadCA(data_ca)
                # question()
            else:
                # print('CAPEs: You were warned for using rude words two times the program will terminate now.')
                # print('CAPES: conversation ends.')
                rude_flag = True
                res = 'You were warned for using rude words two times the program will terminate now.'
                data_ca = (question_result[count], user_input, session['username'], 'stopped',
                           'You were warned for using rude words two times the program will terminate now.')
                uploadCA(data_ca)
                # exit()


def response(word_type, id_g, count, user_input):
    global res
    temp = questionN
    i_val = random.choice([0, 1])
    cursor.execute("SELECT ans2 FROM response Where id_c = ?", [id_g])
    result = cursor.fetchall()
    if id_g == 2:
        if word_type.__contains__('result') | word_type.__contains__('record'):
            # print('CAPEs:', result[0][0])
            res = result[0][0] + "<br /><br /> Now," + temp
            data_ca = (question_result[count], user_input, user, 'continue', result[0][0])
            uploadCA(data_ca)
        else:
            # print('CAPEs:', result[1][0])
            res = result[1][0] + "<br /><br /> Now, " + temp
            data_ca = (question_result[count], user_input, user, 'continue', result[0][0])
            uploadCA(data_ca)
    else:
        resp = result[i_val][0]
        # print('CAPEs:', resp)
        res = resp + "<br /><br /> Now, " + temp
        data_ca = (question_result[count], user_input, user, 'continue', str(resp))
        uploadCA(data_ca)


def checkGeneralKeyword(user_input, count):
    global counter_q
    global res
    temp = questionN
    generalKeyword(user_input, 2)
    general = list_matching
    if len(general) != 0:
        pattern_similarity = patternSimilarity(user_input)
        if pattern_similarity > 0.7:
            response(general, 2, count, user_input)
            # question(count)
    else:
        generalKeyword(user_input, 3)
        weather = list_matching
        if len(weather) != 0:
            pattern_similarity = patternSimilarity(user_input)
            if pattern_similarity > 0.7:
                response(weather, 3, count, user_input)
                # question(count)
        else:
            # TODO remove comment
            # print("CAPEs: Sorry, I did not understand you grimacing_emoji")
            res = "Sorry, I did not understand you grimacing_emoji <br /><br /> " + temp
            data_ca = (question_result[count], user_input, user, 'continue',
                       "Sorry, I did not understand you grimacing_emoji and go next question")
            uploadCA(data_ca)

            # question(count)


def question():
    global counter
    global res
    global inpput
    global counter_q
    global questionN
    if counter > 5:
        """findCertificate()"""
        # exitProgram('f', '')
        # if we have time need to improve
    else:
        questions_joint = questionN
        user_input = inpput
        user_input = removeSpecialCharacters(user_input)
        exitProgram(user_input, questions_joint)
        if not exit_flag:
            rudeKeyword(user_input, counter)  # rude word
            if reapet:
                res = res_rude + questions_joint
            else:
                if not rude_flag:
                    getPattern(counter + 1)
                    getKeyword(user_input, counter + 1)
                    if len(list_matching) != 0:
                        pattern_similarity = patternSimilarity(user_input)
                        if pattern_similarity > 0.7:
                            keyword = ','.join(list_matching)
                            user_input_removed_keywords = "".join(removeKeyword(user_input))
                            for word in non_value:  # check none values
                                if user_input.__contains__(word):
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
                            # print(counter)
                            if counter <= 4:
                                questions_joint = ''.join(
                                    question_result[
                                        counter_q])  # loop over questions_joint table, and save the result in questions_joint
                                questionN = questions_joint
                                res = questions_joint
                            elif counter == 5:
                                # findCertificate()
                                res = findCertificate()

                            counter += 1
                            counter_q += 1
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
    global res, inpput
    if accepted_list.__len__() != 0:
        # print("I found the most matching certificate for you:")
        res = "I found the most matching certificate for you: </br></br>"
        count = 1
        for row in result:
            if row[2] in accepted_list:
                certificate = row[0]
                vendor = row[1]
                exam = row[3]
                link = row[4]

                res += str(
                    count) + "- " + certificate + " provided from " + vendor + " it's own exam is " + exam + " you can see more in <a href=\"" + link + '\">here</a></br></br>'

                data = (user, certificate, vendor, exam, link)
                uploadResult(data)
                count += 1
            else:
                continue
    else:
        # print("Sorry, I can not found the most matching certificate for you")
        res = 'Sorry, I can not found the most matching certificate for you'
        certificate = 'no recommendation'
        vendor = 'no recommendation'
        exam = 'no recommendation'
        link = 'no recommendation'
    exitProgram('f', '')


def q7_check_ans(uniq, result_preC):
    global q_count
    ans = inpput
    data_ca = (res, ans, user, 'continue', 'after those question the result will show')
    uploadCA(data_ca)
    while q_count >= 0:
        if ans.__contains__(str(q_count)):
            try:
                accepted_c.append(uniq[q_count])
            except IndexError:
                pass
        else:
            'noting'
        q_count -= 1
    """if q_count <= 0:
        print_result(accepted_c, result_preC, random_id)"""


def findCertificate():
    global certificate, vendor, exam, link
    global res
    global inpput
    global q_count
    global result_preC
    global uniq
    w = random_id
    # w = 9502

    cursor.execute("SELECT  keywords FROM log WHERE qNumer=?", [w])
    result = cursor.fetchall()
    print(result)
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
            if a[0][0][x].__contains__('computer science'):
                major.append('%cs%')
            elif a[0][0][x].__contains__('computer information system'):
                major.append('%cis%')
            elif a[0][0][x].__contains__('cyber security'):
                major.append('%cys%')
            elif a[0][0][x].__contains__('artificial intelligent'):
                major.append('%ai%')
            elif a[0][0][x].__contains__('%'):
                major.append('%')
            else:
                major.append('%' + a[0][0][x] + '%')
        elif len_m <= 0:
            major.append('')
        len_m -= 1
    # _____________________________________________________________________________
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
    # ____________________________________________________________________________
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
    # _______________________________________________________________________________
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
    # ____________________________________________________________________
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
    # ________________________________________________________________________
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
    result_preC = cursor.fetchall()
    seen = set()
    uniq = []
    # print('result: ',result_preC)
    # to take the duplicate pre-certificate
    for x in result_preC:
        if x[2] not in seen:
            uniq.append(x[2])
            seen.add(x[2])
    # to take the accept certificate
    # accepted_c = []

    count_q7 = uniq.__len__()
    # print('uniq:',uniq)
    qusion7 = ' '
    q_count = 0
    for row in uniq:
        if row != 'NULL':
            # q7 = "Have you taken this pre-certificate", row, "? (yes or no)"
            qusion7 += str(q_count) + '-' + row + '</br>'
        if row == 'NULL':
            accepted_c.append(row)
        q_count += 1
        count_q7 -= 1

    # print(qusion7)
    if qusion7.strip():
        q7 = 'Do you had any certificates form this list? </br>' + qusion7 + ' please enter all <b>numbers</b> for certificates you have.'
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


# ______________________________________________________________-

@app.route('/get')
def get_bot_response():
    global res
    global counter

    userText = request.args.get('msg')
    getinput(userText)
    getQuestion()

    if counter < 6:
        question()
    elif counter == 6:
        q7_check_ans(uniq, result_preC)
        print_result(accepted_c, result_preC, random_id)
        counter += 1
    elif counter > 6:
        # todo: 1- end program 2- reuse it
        # counter = 0
        res = 'If you want to try again reload this page <3'

    x = setinput()

    return str(x)
