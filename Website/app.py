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


app = Flask(_name_)
mail = Mail(app)
if _name_ == '_main_':
    app.run()

# configuration for mail, upload image ,app
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


# Vendor home page
@app.route('/home', methods=["GET", "POST"])
def home():
    #check if user logged in
    if session['logged_in'] == False:  return render_template('Login.html')
    #check request type "if the user click on button the reguest method will be post"
    if request.method == "POST":
        title = request.form['tit']
        return redirect(url_for('edit', pe=title))
        # if the vendor click on edit icon for specific exam,
        # vendor will redirect to updtae funtion with the title of that exam
    #else
    # retrieve exams information for specific vendor by vendor id
    user = session['username'] # get vendor user name
    con = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    with con:
        cur = con.cursor() #create cursor to save query result #create cursor to save query result
        cur.execute("SELECT * FROM certificate WHERE lower(v_username) ='" + user + "'") # query
        rows = cur.fetchall() # get result
    return render_template('home.html', rows=rows) #send result data to the html page


# vendor list page
@app.route('/list', methods=["GET", "POST"])
def ViewListVendors():
    # check if user logged in , if not redirect to login page , if not redirect to login page
    if session['logged_in'] == False:  return render_template('Login.html')
    user = session['username'] # get username
    conn = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    cursor = conn.cursor() #create cursor to save query result
    result = cursor.execute(" SELECT * FROM  vendor ") # query
    rows = result.fetchall() # get result
    return render_template('beneficiary/vendor-list.html', c=rows)#send result data to the html page


# vendor details page
@app.route('/de/<v_username>', methods=["GET", "POST"])
def ViewVendorDetails(v_username):
    # check if user logged in , if not redirect to login page
    if session['logged_in'] == False:  return render_template('Login.html')
    user = session['username'] # get username
    conn = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    cursor = conn.cursor() #create cursor to save query result
    result = cursor.execute(" SELECT * FROM  vendor where v_username ='" + v_username + "'") # query
    with conn:
        cur = conn.cursor() #create cursor to save query result
        cur.execute("SELECT * FROM certificate WHERE lower(v_username) ='" + v_username + "'") # query
        rows = cur.fetchall() # get result
    return render_template('beneficiary/vendor-details.html', c=result, users=v_username, user=user, rows=rows)#send result data to the html page


# Beneficiary  recommecndation page
@app.route('/recommendation')
def RecommendationPEs():
    # check if user logged in , if not redirect to login page
    if session['logged_in'] == False:  return render_template('Login.html')
    conn = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    cursor = conn.cursor() #create cursor to save query result
    cursor.execute(" SELECT * FROM result where b_id='" + session['username'] + "'") # query
    result = cursor.fetchall() # get result
    return render_template('beneficiary/recommendation.html', rows=result)#send result data to the html page


# todo ?
# beneficiary home page
@app.route('/bhome')
def Bhome():
    # check if user logged in , if not redirect to login page
    if session['logged_in'] == False:  return render_template('Login.html')
    print(session['username'])
    session['counter'] = 0
    session['exam'] = []
    session['link'] = []
    session['vendor'] = []
    session['certificate'] = []
    session['list_matching'] = []
    session['question_result'] = []
    session['training_pattern'] = []
    session['training_keyword'] = []
    session['accepted_c'] = []
    session['result_preC'] = []
    session['uniq'] = []
    session['rude_counter'] = 0
    session['res'] = ''
    session['inpput'] = ''
    session['count_q7'] = 1
    session['counter_q'] = 1
    session['rude_flag'] = False
    session['questionN'] = 'What is your major?'
    session['temp'] = ' '
    session['exit_flag'] = False
    session['reapet'] = False
    session['res_rude'] = ''
    session['q_count'] = 0
    return render_template('beneficiary/home.html')# redirect to the html page


# vendor add PE page
@app.route("/add", methods=["GET", "POST"])
def add():
    # check if user logged in , if not redirect to login page
    if session['logged_in'] == False:  return render_template('Login.html')
    #check request type "if the user click on button the reguest method will be post"
    if request.method == "POST":
        #store information vendor entered into proper variable
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

        conn = sqlite3.connect('CAPEsDatabase.db') # connect to the database
        cursor = conn.cursor() #create cursor to save query result
        cursor.execute('INSERT INTO certificate VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', (
            None, title, v_username, major, level, field, pre_req, pre_c, prog_l, duration, description, exam_name,URLlink))# query
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('home'))# Redirect to vendor home page in case of succesfully added
    return render_template("vendor/add.html")# Redirect to add page in case of unsuccesfully added


# vendor edit PE page
@app.route('/edit/<pe>', methods=['GET', 'POST'])
def edit(pe):# edit function take PE_id as parameter
    # check if user logged in , if not redirect to login page
    if session['logged_in'] == False: return render_template('Login.html')
    # check request type "if the request method equal Get then retreve data from the database"

    if request.method == "GET":
        conn = sqlite3.connect('CAPEsDatabase.db') # connect to the database
        cursor = conn.cursor() #create cursor to save query result
        result = cursor.execute(" SELECT * FROM  certificate where p_id='" + pe + "'")# query
        return render_template('vendor/edit.html', info=result) #send result data to the html page

    #check request type "if the user click on button the reguest method will be post"
    if request.method == "POST":
        # store information vendor entered into proper variable
        title = request.form['title']
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

        conn = sqlite3.connect("CAPEsDatabase.db") # connect to the database
        cursor = conn.cursor() #create cursor to save query result
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
                       "' WHERE  p_id='" + pe + "';")# query
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('home'))# Redirect to vendor home page in case of succesfully edit
    return render_template("vendor/edit.html")# Redirect to edit page in case of unsuccesfully edit


# delete vendor info page
@app.route('/delete/<pe>', methods=['GET', 'POST'])
def delete(pe): #delete  function take PE_id as parameter
    # check if user logged in , if not redirect to login page
    if session['logged_in'] == False: return render_template('Login.html')
    conn = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    cursor = conn.cursor() #create cursor to save query result
    cursor.execute('DELETE FROM certificate WHERE p_id=?', (pe,))# query
    conn.commit()
    return redirect(url_for('home'))# Redirect to vendor home page



# reset password page
@app.route('/resetpassword')
def resetpassword():
    return render_template('resetpassword.html')# redirect to the html page


# login page
@app.route('/', methods=['GET', 'POST'])
def Login():
    # check if user logged in , if not redirect to login page
    session['logged_in'] = False # set session logged in false
    error = None #set error none
    # check request type "if the user click on button the request method will be post"
    if request.method == 'POST':
        # store user information entered into proper variable
        username = request.form['username']
        password = request.form['password']

        completion = b_validate(username, password)#send username and  password to beneficiary validate
        #check if user is a beneficiary, where completion status = ture
        if completion == False:
            # send username and  password to vendor validate
            completion = v_validate(username, password)
            # check if user is a vendor, where completion status = ture
            if completion == False:
                # if user not beneficiary or vendor set error message
                error = 'Invalid Credentials. Please try again.'
            else:
                session['logged_in'] = True #set flage logeed in to true
                return redirect(url_for('home'))#in case vlaid vendor redirect to vendor home page
        else:
            session['logged_in'] = True #set flage logeed in to true
            return redirect(url_for('Bhome')) #in case vlaid beneficiary redirect to beneficiary home page

    return render_template('Login.html', error=error)# redirect to the html page with error data


# method for beneficiary login
def b_validate(username, password):
    con = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    completion = False #set completion to false
    with con:
        cur = con.cursor() #create cursor to save query result
        cur.execute("SELECT * FROM beneficiary")# query
        rows = cur.fetchall() # get result
        for row in rows: # fetch  each row in data base
            # store username and password into proper variable
            dbUser = row[0]
            dbPass = row[1]
            if ((dbUser == username) and (dbPass == password)):# check if user entries match with data in the data database
                session['username'] = dbUser #set session username with beneficiary
                completion = True #set completion to true
    return completion


# method for vendor login
def v_validate(username, password):
    con = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    completion = False  #set completion to false
    with con:
        cur = con.cursor() #create cursor to save query result
        cur.execute("SELECT * FROM vendor")# query
        rows = cur.fetchall() # get result
        for row in rows:
            # store username and password into proper variable
            dbUser = row[0]
            dbPass = row[1]
            if dbUser == username and dbPass == password:# check if user entries match with data in the data database
                session['username'] = dbUser #set session username with vendor
                completion = True #set completion to true
    return completion


# logout
@app.route('/logout')
def logout():
    return redirect(url_for('Login')) # redirect to log in home page


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    error = None # set error message to none
    # check request type "if the user click on button the request method will be post"
    if request.method == 'POST':
        # store token, password, confirm password into proper variable
        token = request.form['Token']
        password = request.form['password']
        ConfirmPassword = request.form['ConfirmPassword']
        con = sqlite3.connect('CAPEsDatabase.db') # connect to the database
        cur = con.cursor() #create cursor to save query result
        with con:
            cur.execute("SELECT * FROM ResetPassword")# query
            rows = cur.fetchall() # get result
            for row in rows:
                # store username and token into proper variable
                Token = row[1]
                username = row[0]
                if token == Token and username == session['username']:# if match with data from database
                    if password == ConfirmPassword:# password, Confirm Password match
                        if session['table'] == 'vendor': # session table contain vendor table name
                            cur.execute(" UPDATE vendor SET password ='" + password + "' Where v_username='" + session['username'] + "'")# query
                            cur.execute('DELETE FROM ResetPassword WHERE username=?', (session['username'],))# query
                            con.commit()
                            return redirect(url_for('Login')) # redirect to login page
                        elif session['table'] == 'beneficiary': # session table contain beneficiary table name
                            cur.execute(
                                " UPDATE beneficiary SET password ='" + password + "' Where b_username='" + session['username'] + "'")# query
                            cur.execute('DELETE FROM ResetPassword WHERE username=?', (session['username'],))# query
                            con.commit()
                            return redirect(url_for('Login'))# redirect to login page
                        else:
                            con.commit()
                    else:
                        error = "Password and Confirm Password fields not matching"# set error message if password, Confirm Password does not match
                        return render_template('resetpassword.html', error=error)#redirect to html page with error mesaage
                else:
                    error = "Please enter a valid token"
                    return render_template('resetpassword.html', error=error)# set error message if  invalied token
    return render_template('resetpassword.html', error=error)#redirect to html page with error mesaage


# method for vendor login
def E_validate(Email):
    completion = False #set completion to false
    con = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    with con:
        cur = con.cursor() #create cursor to save query result
        cur.execute("SELECT * FROM vendor")# query
        rows = cur.fetchall() # get result
        for row in rows:# fetch each row
            # store email into proper variable
            email = row[3]
            if email.lower() == Email.lower():# if match with data from database
                completion = True #set completion to true
                con.commit()
                session['table'] = 'vendor' #set session value to "vendor"
                return (completion, row[0]) # return the vendor usernaem and completion status
            else:
                with con:
                    cur.execute("SELECT * FROM beneficiary")# query
                    rows = cur.fetchall() # get result
                    for row in rows: # fetch each row
                        # store email into proper variable
                        email = row[3]
                        if email.lower() == Email.lower():# if match with data from database
                            completion = True #set completion to true
                            con.commit()
                            session['table'] = 'beneficiary' #set session value to "beneficiary"
                            return (completion, row[0]) # return the beneficiary usernaem and completion status
    if completion == False:
        return (completion, None) # return none completion status if completion is flase


def sendmassage(token, email):
    #send message take token and user email as parameter
    #then send message with title and sender email and email body with token
    msg = Message('Reset Password', sender='2020capes@gmail.com', recipients=[email])
    msg.body = "Hello \nDear user use this token to reset your password : " + token
    mail.send(msg) # send the emqil
    return None


def get_random_string(length=5, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    # this function to generate random token of lenght 5 digit
    return ''.join(random.choice(allowed_chars) for i in range(length))


@app.route('/forgot', methods=['GET', 'POST'])
def ForgotPassword():
    error = None
    # check request type "if the user click on button the request method will be post"
    if request.method == 'POST':
        # store user information entered into proper variable
        email = request.form['email']
        completion, username = E_validate(email)# send email to email validate function
        if completion == False:
            error = 'Invalid Credentials. Please try again.' # set error message
            return render_template('forgetpassword.html', error=error)# return to html page with error message
        elif completion == True and username is not None:
            token = get_random_string() # call function to generate random token
            con = sqlite3.connect('CAPEsDatabase.db') # connect to the database
            cur = con.cursor() #create cursor to save query result
            cur.execute('INSERT INTO ResetPassword VALUES (?,?)', (username, token))# query
            con.commit()
            cur.close()
            con.close()
            sendmassage(token, email) # call send message function with token and user email
            session['username'] = username # set session with username
            return redirect(url_for('reset')) # redirect user to reset password page
    if request.method == 'GET': # if request method is get
        return render_template('forgetpassword.html', error=error)# return to html page with error message



# ________

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
        data_ca = (quz, x, session['username'], 'stopped',
            "Conversation ends. Bye!" + wave_emoji)
        uploadCA(data_ca)
        session['exit_flag'] = True

    elif x == 'f':
        session['res'] += " </br>Thank you for using CAPEs, Best wishes!" + smile_emoji + \
               "</br></br>Please, help us to improve CAPEs by completing this survey: " \
               "<a href=\"https://forms.gle/PCjbY7Znetn8xNQA9\">here</a>"
        data_ca = (quz, x, session['username'], 'complete', "Thank you for using CAPEs, Best wishes!" + smile_emoji)
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
    print('__genKey__',result)
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
        # user_input_cleaned = lemmatize(user_cleaned)
        token1 = nlp(user_cleaned)
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
    # temp = session['temp']
    questionN = session['questionN']
    temp = session['questionN']
    i_val = random.choice([0, 1])
    cursor.execute("SELECT ans2 FROM response Where id_c = ?", [id_g])
    result = cursor.fetchall()
    # todo
    print("___________resp-----")
    print(word_type, id_g, count, user_input)
    if id_g == 2:
        if word_type._contains('result') | word_type.contains_('record'):
            session['res'] = result[0][0] + "<br /><br /> Now," + temp
            data_ca = (question_result[count], user_input, session['username'], 'continue', result[0][0])
            uploadCA(data_ca)
        else:
            session['res'] = result[1][0] + "<br /><br /> Now, " + temp
            data_ca = (question_result[count], user_input, session['username'], 'continue', result[0][0])
            uploadCA(data_ca)
    else:
        resp = result[i_val][0]
        session['res'] = resp + "<br /><br /> Now, " + temp
        data_ca = (question_result[count], user_input, session['username'], 'continue', str(resp))
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
        print('_____enter gen______')
        pattern_similarity = patternSimilarity(user_input)
        print("ENTERD****", pattern_similarity)
        if pattern_similarity > 0.7:
            # todo
            print("ENTERD****")
            response(session['list_matching'], 2, count, user_input)
        else:
            # todo print
            print('_____enter weth______')
            generalKeyword(user_input, 3)
            # todo print
            print('wether', session['list_matching'])
            weather = session['list_matching']
            if len(weather) != 0:
                # todo print
                print('_____enter weth2______')
                pattern_similarity = patternSimilarity(user_input)
                print("*****pattern_similarity ****", pattern_similarity)
                if pattern_similarity > 0.65:
                    response(session['list_matching'], 3, count, user_input)
                else:
                    # todo print
                    print('_____enter soory______')
                    session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
                    data_ca = (question_result[count], user_input, session['username'], 'continue',
                               "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
                    uploadCA(data_ca)
            else:
                # todo print
                print('_____enter soory______')
                session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
                data_ca = (question_result[count], user_input, session['username'], 'continue',
                           "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
                uploadCA(data_ca)
    else:
        #todo print
        print('_____enter weth______')
        generalKeyword(user_input, 3)
        #todo print
        print('wether',session['list_matching'])
        weather = session['list_matching']
        if len(weather) != 0:
            #todo print
            print('_____enter weth2______')
            pattern_similarity = patternSimilarity(user_input)
            #todo
            print("pattern_similarity", pattern_similarity)
            if pattern_similarity > 0.65:
                response(session['list_matching'], 3, count, user_input)
            else:
                # todo print
                print('_____enter soory______')
                session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
                data_ca = (question_result[count], user_input, session['username'], 'continue',
                           "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
                uploadCA(data_ca)
        else:
            #todo print
            print('_____enter soory______')
            session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
            data_ca = (question_result[count], user_input, session['username'], 'continue',
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
                            print('list mathc for key_____', session['list_matching'])
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

                            data_ca = (questions_joint, user_input, session['username'], 'continue', responss)
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
                data = (session['username'], certificate, vendor, exam, link)
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
    data_ca = (res, ans, session['username'], 'continue', 'after those question the result will show')
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
    # _________
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
    # __________
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
    # _________
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
    # ________
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
    # ________
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


# ________

@app.route('/get')
def get_bot_response():

    counter = session['counter']
    userText = request.args.get('msg')
    getinput(userText)
    getQuestion()

    if counter < 6:
        question()
    elif session['counter'] == 6:
        q7_check_ans(session['uniq'])
        session['counter'] += 1
        print_result(session['accepted_c'], session['result_preC'], random_id)
    elif session['counter'] > 6:
        session['res'] = 'If you want to try again reload this page <3'

    x = setinput()

    return str(x)
