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


app = Flask(__name__)
mail = Mail(app)
if __name__ == '__main__':
    app.run()

# configuration for mail, upload image ,app
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/logos/'
app.secret_key = 'CAPEs secret key CAPEs'
app.config['SESSION_TYPE'] = 'null'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
#app.config['MAIL_PORT'] = 587
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '2020capes@gmail.com'
#app.config['MAIL_PASSWORD'] = 'Senoritas2020'
app.config['MAIL_PASSWORD'] = 'fzlesmygrpwjnbxq'
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
    cursor.execute("SELECT MIN(r_id) AS r_id, b_id, certificate, vendor ,exam ,link FROM result where b_id='" + session['username'] + "' GROUP BY certificate") # query
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
    session['random_id'] = randomID()
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
        cursor.execute(" SELECT exams FROM certificate where p_id='" + pe + "'")
        exam_title = cursor.fetchall()
        cursor.execute("UPDATE certificate SET name='" + title   +
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
        print(exam_title)
        cursor.execute("UPDATE result SET certificate='" + title +
                       "', exam='" + exam_name +
                       "', link='" + URLlink +
                       "' WHERE  exam='" +exam_title[0][0] + "';")  # query
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
    cursor.execute("SELECT exams FROM certificate where p_id='" + pe + "'")#query
    exam_title = cursor.fetchall()
    cursor.execute('DELETE FROM certificate WHERE p_id=?', (pe,))# query
    cursor.execute('DELETE FROM result WHERE exam=?',(exam_title[0][0],))# query
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
        completion = token_validate(session['username'] , token)  # send username and  password to beneficiary validate
                # check if exist username and token , where completion status = ture
        if completion == True :
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

# method for token validate
def token_validate(username, token):
    con = sqlite3.connect('CAPEsDatabase.db') # connect to the database
    completion = False #set completion to false
    with con:
        cur = con.cursor() #create cursor to save query result
        cur.execute("SELECT * FROM ResetPassword")# query
        rows = cur.fetchall() # get result
        for row in rows: # fetch  each row in data base
            # store username and token into proper variable
            dbUser = row[0]
            dbtoken = row[1]
            if ((dbUser == username) and (dbtoken == token)):# check if user entries match with data in the data database
                completion = True #set completion to true
    return completion


# ________________________ CAPEs_________________________________

nlp = spacy.load("en_core_web_md")
warnings.simplefilter("error", UserWarning)
connection = sqlite3.connect('CAPEsDatabase.db', check_same_thread=False)
cursor = connection.cursor()


# genaret random number for chat
def randomID():
    cursor.execute("SELECT qNumer FROM log")
    result = [i[0] for i in cursor.fetchall()] # save the result
    i = random.randint(0, 10000) # genarate random number
    if i not in result: # check if i is not in the result
        return i
    else: # if is in the database re-generate random again
        return randomID()


wave_emoji = emoji.emojize(':wave:', use_aliases=True)
smile_emoji = emoji.emojize(':smile:', use_aliases=True)
thumbs_emoji = emoji.emojize(':thumbs_up:', use_aliases=True)
grimacing_emoji = emoji.emojize(':grimacing:', use_aliases=True)


# take the user input and save it in session
def getinput(input):
    session['inpput'] = input.lower()


# take the chat response to pass it to html interface
def setinput():
    res = session['res']
    # todo print
    print('res from setinput()', res)
    return res



non_value = ['no', 'neither', 'not', 'non', 'all', 'every', 'dont', 'both', 'any', 'each', 'nothing', 'nor']


# take the questions from database and save it in session
def getQuestion():
    # question_result = session['question_result']
    cursor.execute("SELECT question FROM questions")
    session['question_result'] = [i[0] for i in cursor.fetchall()]
    print('question_result in getQuestion() ', session['question_result'])


# check if user typed 'q' to finsh chating or if the program end by the chat it self 'f'
def exitProgram(x, quz):

    if x == 'q':
        session['res'] = "Conversation ends. Bye!" + wave_emoji + "</br> </br> If you want to try again reload this page <3"
        data_ca = (quz, x, session['username'], 'stopped',
            "Conversation ends. Bye!" + wave_emoji)
        uploadCA(data_ca) # upload in ca table
        session['exit_flag'] = True # make exit flag session true

    elif x == 'f':
        session['res'] += " </br>Thank you for using CAPEs, Best wishes!" + smile_emoji + \
               "</br></br>Please, help us to improve CAPEs by completing this survey: " \
               "<a href=\"https://forms.gle/PCjbY7Znetn8xNQA9\">here</a>"
        data_ca = (quz, x, session['username'], 'complete', "Thank you for using CAPEs, Best wishes!" + smile_emoji)
        uploadCA(data_ca) # upload in ca table
        session['exit_flag'] = True # make exit flag session true


# get the pattern form pattern table by the id_r for each question
def getPattern(query):
    training_pattern = session['training_pattern']
    training_pattern.clear() # clear the arayy before use again
    print('qury', query)
    cursor.execute("SELECT anwser_p FROM pattern Where id_r = ?", [query])
    patterns = cursor.fetchall() # save result
    for row in patterns: # add each pattern in the list
        training_pattern.append(row[0])

    print('training_pattern from getPattern()', training_pattern)
    return training_pattern


# take the keyword from session['list_matching'] and remove it from user input
def removeKeyword(user_input):
    list_matching = session['list_matching']
    print('list_matching from removeKeyword()', list_matching)
    keys = ' '.join(list_matching).split() # aggregation all keyword in the list matching
    removed_keyword = ' '.join(word for word in user_input.split() if word not in keys) # aggregation all word without the key word in the list matching
    return removed_keyword


# get keyword for id_r quesion from kerword table then find the match keyword from user input if thier is by using SequenceMatcher and save it in session
def getKeyword(user_input, query):
    list_matching = session['list_matching']
    list_matching.clear() # clear the arayy before use again
    training_keyword = session['training_keyword']
    training_keyword.clear() # clear the arayy before use again
    cursor.execute("SELECT keyword FROM keyword Where id_r = ?", [query])
    keyword = cursor.fetchall() # save result
    print('user input from getKeyword()', user_input)
    print('keyword from getKeyword()', keyword)
    for row in keyword:
        training_keyword.append(row[0])
        match = SequenceMatcher(None, user_input, row[0]).find_longest_match(0, len(user_input), 0, len(row[0]))
        list_matching.append(row[0][match.b: match.b + match.size])
        list_matching = list(set(list_matching).intersection(set(training_keyword)))
        session['list_matching'] = list(set(list_matching).intersection(set(training_keyword)))

    print("training_keyword from getKeyword()", training_keyword)
    print('list_matching from getKeyword()', list_matching)


# by using regular expertion this function remove the unwanted charcers like: /$%^...
def removeSpecialCharacters(user_input):
    patterns = r'[^a-zA-z0-9 #+\s]' # the regular experation condtion
    user_input_removed_char = re.sub(patterns, '', user_input) # aggregation all word after remove the unwanted charcers
    return user_input_removed_char


# this function use nltk(nlp) and word.net to make each word in user input back to root.
def lemmatize(user_input):
    lemmatizer = WordNetLemmatizer()
    user_input_lemmatized = ' '.join(lemmatizer.lemmatize(w) for w in nltk.word_tokenize(user_input))
    return user_input_lemmatized


# get general keyword for id_c quesion from kerword table then find the match keyword from user input if thier is by using SequenceMatcher and save it in session
def generalKeyword(user_input, query):
    list_matching = session['list_matching']
    list_matching.clear() # clear the arayy before use again
    training_keyword = session['training_keyword']
    training_keyword.clear() # clear the arayy before use again
    cursor.execute("SELECT keyword FROM keyword Where id_c = ?", [query])
    result = cursor.fetchall() # save the result

    print('general Keywords from generalKeyword()',result)
    for row in result:
        training_keyword.append(row[0])
        match = SequenceMatcher(None, user_input, row[0]).find_longest_match(0, len(user_input), 0, len(row[0]))
        list_matching.append(row[0][match.b: match.b + match.size])
        list_matching = list(set(list_matching).intersection(set(training_keyword)))
        session['list_matching'] = list(set(list_matching).intersection(set(training_keyword)))

    print('list matching from generalKeyword()', session['list_matching'])


# this function use spacy to calculate the similarty between the user input and each pattern in database for spicefic question then return the max
def patternSimilarity(user_input):
    training_pattern = session['training_pattern']

    print('form patternSimilarity() training_pattern', training_pattern)
    user = removeKeyword(user_input) # call this function to remove keyword
    user_cleaned = removeSpecialCharacters(user) # call this function to remove unwanted Characters

    print('user_cleaned form patternSimilarity()', user_cleaned)
    similarity_list = []
    if len(user_cleaned) > 0: # if the user cleand sentence not empty do the similarty
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
    else: # else -which mean the user enter just keyword without any addtional word- return 1
        return 1


# this function take the user in put to check if it contain a rude word if thier is it will give warning in first time. at 3rd time it will end cinversation.
def rudeKeyword(user_input, count):
    questionN = session['questionN']
    question_result = session['question_result']
    session['list_matching'] = [ ]
    session['reapet'] = False
    #todo print
    print('---------------rude-----------------------')
    print('rude count from rudeKeyword()', session['rude_counter'])
    print('questionN from rudeKeyword()', questionN)
    print('list Matching from rudeKeyword()', session['list_matching'])

    generalKeyword(user_input, 4) # call rude word from database
    #todo print
    print('list Matching after', session['list_matching'])
    for word in session['list_matching']:
        if user_input.__contains__(word):
            #todo print
            print('enter thier is rude')
            if session['rude_counter'] < 2:
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


# this function take the response of the general keyword from database table response according to id_g which mean the id of the geneal type in database.
def response(word_type, id_g, count, user_input):

    question_result = session['question_result']
    temp = session['questionN']
    i_val = random.choice([0, 1])
    cursor.execute("SELECT ans2 FROM response Where id_c = ?", [id_g])
    result = cursor.fetchall()
    print("____________response value in response()________________")
    print(word_type, id_g, count, user_input)
    if id_g == 2:
        if word_type.__contains__('result') | word_type.__contains__('record'):
            session['res'] = result[0][0] + "<br /><br /> Now, " + temp
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


# take the user input to see if it is general by pass id general to generalKeyword to get the list matching the test the similrty. if not then check if it is weather and repeat the steps like in general. if not the massage will appear that system can not understand the input.
def checkGeneralKeyword(user_input, count):
    temp = session['temp']
    question_result = session['question_result']
    questionN = session['questionN']
    temp = questionN
    generalKeyword(user_input, 2) # call general word from database
    general = session['list_matching']
    print('list mtach vluae in checkGeneralKeyword():', session['list_matching'], len(session['list_matching']))
    if len(general) != 0:
        print('_____enter general case______')
        pattern_similarity = patternSimilarity(user_input)
        print("pattern_similarity in checkGeneralKeyword()", pattern_similarity)
        if pattern_similarity > 0.7:
            print("ENTERD to get response")
            response(session['list_matching'], 2, count, user_input) # call this function to get the response
        else:
            print('_____enter weather case______')
            generalKeyword(user_input, 3) # call weather word from database
            print('wether list matching', session['list_matching'])
            weather = session['list_matching']
            if len(weather) != 0:
                print('_____enter wether2______')
                pattern_similarity = patternSimilarity(user_input)
                print("*****pattern_similarity ****", pattern_similarity)
                if pattern_similarity > 0.65:
                    response(session['list_matching'], 3, count, user_input) # call this function to get the response
                else:
                    # todo print
                    print('_____enter sorry______')
                    session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
                    data_ca = (question_result[count], user_input, session['username'], 'continue',
                               "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
                    uploadCA(data_ca)
            else:
                print('_____enter sorry______')
                session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
                data_ca = (question_result[count], user_input, session['username'], 'continue',
                           "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
                uploadCA(data_ca)
    else:
        print('_____enter weather case______')
        generalKeyword(user_input, 3) # call general word from database
        print('weather list matching',session['list_matching'])
        weather = session['list_matching']
        if len(weather) != 0:
            print('_____enter weth2______')
            pattern_similarity = patternSimilarity(user_input)
            print("pattern_similarity", pattern_similarity)
            if pattern_similarity > 0.65:
                response(session['list_matching'], 3, count, user_input) # call this function to get the response
            else:
                print('_____enter sorry______')
                session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
                data_ca = (question_result[count], user_input, session['username'], 'continue',
                           "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
                uploadCA(data_ca)
        else:
            #todo print
            print('_____enter sorry______')
            session['res'] = "Sorry, I did not understand you" + grimacing_emoji + " <br /><br /> " + temp
            data_ca = (question_result[count], user_input, session['username'], 'continue',
                       "Sorry, I did not understand you" + grimacing_emoji + "and go next question")
            uploadCA(data_ca)


# the main function it is show all question in order.
def question():
    counter = session['counter']
    inpput = session['inpput']
    counter_q = session['counter_q']
    questionN = session['questionN']
    question_result = session['question_result']
    questions_joint = session['questionN']
    user_input = inpput # user input
    """if user_input.__contains__('ing'):
        print('------------------------E---------------------------')
        user_input = ''.join(user_input.split())[:-3]
    else:
        print('------------------------N---------------------------')

        user_input"""
        
    print('qus', questions_joint)
    print('use input', user_input)
    user_input = removeSpecialCharacters(user_input) # remove unwanted Character from the input
    exitProgram(user_input, questions_joint) # check the input if it is equl 'q'
    if not session['exit_flag']: # if the flag = Flase
        rudeKeyword(user_input, session['counter'])  # check rude word
        if session['reapet']: # if reapet true that mean user type rude word so print wurning and repeat the quesion
            session['res'] = session['res_rude'] + session['questionN']
        else:
            if not session['rude_flag']: # if flag = Flase
                print('count+1', counter + 1)
                getPattern(counter + 1) # get the pattern of the quesion x
                getKeyword(user_input, counter + 1) # get the keyword of the quesion x
                if len(session['list_matching']) != 0: # if there is a match keyword enter if condetion
                    pattern_similarity = patternSimilarity(user_input) # count the similartiy and save the value in pattern_similarity
                    print("pattern_similarity", pattern_similarity)
                    if pattern_similarity > 0.7:
                        print('list maching _____', session['list_matching'])
                        keyword = ','.join(session['list_matching']) # gathering the keyword in keyword varibale and put beetwen them , .
                        user_input_removed_keywords = "".join(removeKeyword(user_input)) # the user input without keyword
                        for word in non_value:  # check none values
                            if user_input.__contains__(word):
                                keyword = "%" # to accepte in database
                        data = (
                            session['random_id'], user_input, user_input_removed_keywords, keyword, pattern_similarity,
                            questions_joint)
                        uploadLog(data) # upload in log table
                        if counter == 5: # if the user reach the 6th quesion
                            responss = 'pre-cretificat q'
                        else:
                            responss = question_result[counter + 1]

                        data_ca = (questions_joint, user_input, session['username'], 'continue', responss)
                        uploadCA(data_ca) # upload in ca table
                        if counter <= 4:
                            questions_joint = ''.join(question_result[counter_q])  # loop over questions_joint table, and save the result in questions_joint
                            # todo print
                            session['questionN'] = questions_joint
                            session['res'] = questions_joint
                            # todo print
                            print('questionN', questionN)
                            print('res', session['res'])
                        elif counter == 5:
                            session['res'] = findCertificate()
                        session['counter'] += 1
                        print('counter', counter)
                        session['counter_q'] += 1
                        print('counterq', counter_q)
                    else: # if the similarty <0.7
                        checkGeneralKeyword(user_input, counter)
                else: # if list matching = 0
                    checkGeneralKeyword(user_input, counter)


# insert the keyword of each question in log table.
def uploadLog(data):
    cursor.execute(
        "INSERT INTO log (qNumer, userAns, textWithOutKey, keywords , patternAsimilarity, question) "
        "VALUES (?, ?, ?, ?, ?, ?)", data)
    connection.commit()


# print the final result
def print_result(accepted_list, result, w):
    certificate = session['certificate']
    vendor = session['vendor']
    exam = session['exam']
    link = session['link']
    print('accepted_list in print_result', accepted_list)
    print('result in print_result', result)
    if accepted_list.__len__() != 0: # if there is result have found print it
        session['res'] = "I found the most matching certificate for you: </br></br>"
        count = 1
        for row in result:
            if row[2] in accepted_list: # if the certificate that have pre_certificate had taken add it
                certificate = row[0]
                vendor = row[1]
                exam = row[3]
                link = row[4]
                session['res'] += str(count) + "- " + certificate + ".</br></br>"
                data = (session['username'], certificate, vendor, exam, link)
                uploadResult(data) # uplaod the result
                count += 1
            else:
                continue
        session['res'] += 'If you want more information you can go to <b>Recommendation</b> tab</br>'
    else: # if there is not any result
        # print("Sorry, I can not found the most matching certificate for you")
        session['res'] = 'Sorry, I could not found the most matching certificate for you' + grimacing_emoji
    exitProgram('f', '') # then end the porogram


# take the anwser of the 7th qusetion and accordeing to the result save the final rsutlt.
def q7_check_ans(uniq):
    q_count = session['q_count']
    print('q_count in q7' , q_count)
    print('uniq in q7', uniq)
    ans = session['inpput'] # take the user anwser from the session
    res = session['res']

    data_ca = (res, ans, session['username'], 'continue', 'after those question the result will show')
    uploadCA(data_ca) # upload to ca table
    while q_count >= 0:
        if ans.__contains__(str(q_count)): # if the user input countain the q_count then add to session
            try:
                session['accepted_c'].append(uniq[q_count])
            except IndexError: # if index error happend just pass. it happend when user enter number greater then the length of uniq
                pass
        else:
            'noting' # do nothing
        q_count -= 1
        session['q_count'] -= 1
    print('accepted ones', session['accepted_c'])


# this function to genarate quesion 7
def findCertificate():
    uniq = session['uniq']
    w = session['random_id']
    # w = 9502

    cursor.execute("SELECT  keywords FROM log WHERE qNumer=?", [w]) # take the keywords from log table by the id of chat
    result = cursor.fetchall()
    # todo print
    print('result',result)
    a = [] # add the keyword here
    for k in range(1):
        a.append([])
        for j in range(6):
            a[k].append([])
            values = str(result[j][0]).split(",")
            for v in values:
                # print(result[k][i])
                a[k][j].append(v)
    # for access a q1
    #print(a[0][0][0])
    major = []
    len_m = len(a[0][0])
    for x in range(0, 3): # if case the user enter more than one keyword for each question. it give user  changes to enter at most 3 keyword
        if len_m > 0:
            if a[0][0][x].__contains__('computer science'): # this mean if user enter the keyword in way that not known in certificate table but has same meaning to the accepte one than we will replace it to this acepte one.
                major.append('%cs%') # when we put % this mean in database get the major that contain the cs like csciscys will accepte in this case.
            elif a[0][0][x].__contains__('computer information system') or a[0][0][x].__contains__('information system') :
                major.append('%cis%')
            elif a[0][0][x].__contains__('cyber security'):
                major.append('%cys%')
            elif a[0][0][x].__contains__('artificial intelligent') or a[0][0][x].__contains__('artificial intelligence'):
                major.append('%ai%')
            elif a[0][0][x].__contains__('%'): # this happend when user use ine of non values.
                major.append('%')
            else:
                major.append('%' + a[0][0][x] + '%')
        elif len_m <= 0:
            major.append('') # if user eneter on keyword then put in other cell nothing
        len_m -= 1
    # _________
    level = []
    len_l = len(a[0][1])
    max = 0
    asnum = 0
    for x in range(0, 3):
        if len_l > 0:
            if a[0][1][x] in "one" or a[0][1][x] in "first":
                asnum = 1
            elif a[0][1][x] in "two" or a[0][1][x] in "second":
                asnum = 2
            elif a[0][1][x] in "three" or a[0][1][x] in "third":
                asnum = 3
            elif a[0][1][x] in "four" or a[0][1][x] in "fourth":
                asnum = int(4)
            elif a[0][1][x] in "five" or a[0][1][x] in "fifth":
                asnum = int(5)
            elif a[0][1][x] in "six" or a[0][1][x] in "sixth":
                asnum = int(6)
            elif a[0][1][x] in "seven" or a[0][1][x] in "seventh":
                asnum = int(7)
            elif a[0][1][x] in "eight" or a[0][1][x] in "eighth":
                asnum = int(8)
            elif a[0][1][x] in "nine" or a[0][1][x] in "ninth":
                asnum = int(9)
            elif a[0][1][x] in "ten" or a[0][1][x] in "tenth":
                asnum = int(10)
            elif a[0][1][x] in "%":
                asnum = int(10)
            else:
                asnum = int(a[0][1][x])
        if asnum > max:
            max = asnum
        len_l -= 1
    level.append(max)

    # __________
    filed = []
    len_f = len(a[0][2])
    for x in range(0, 3):
        if len_f > 0:

            if a[0][2][x] in "oop" or a[0][2][x] in "object oriented programming":
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
            if a[0][3][x] in "html5":
                program_language.append("%html%")
            elif a[0][3][x] in "css3":
                program_language.append("%css%")
            elif a[0][3][x] in "c sharp":
                program_language.append("%c#%")
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
            elif a[0][4][x] in "red hat" :
                vendor_name.append("%red hat academy%")
            elif a[0][4][x] in "%":
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

    print("the keyword of each question in findcetificate()", major,level,filed,program_language,vendor_name,duration)
    cursor.execute(
        "SELECT name , v_username , pre_c , exams , urllink FROM certificate WHERE (major like ? or major like ? or major like ?)and (level <= ?) and (field like ? or field like ? or field like ? ) and (prog_l like ? or prog_l like 'null' or prog_l like ? or prog_l like ?)and (v_username like ? or v_username like ? or v_username like ?) and (duration like ? or duration like ? or duration like ?)",
        (major[0], major[1], major[2], level[0], filed[0], filed[1], filed[2],
         program_language[0],
         program_language[1], program_language[2], vendor_name[0], vendor_name[1], vendor_name[2], duration[0],
         duration[1], duration[2])) # this qury to get the certificate by take the user inputs. it will call from each one the name, vendor name, pre-cretificate and the link
    session['result_preC'] = cursor.fetchall()
    #todo print
    print('result after filter', session['result_preC'])
    seen = set()
    uniq = [] # to take the duplicate pre-certificate
    for x in session['result_preC']:
        if x[2] not in seen:
            session['uniq'].append(x[2])
            seen.add(x[2])

    session['count_q7'] = session['uniq'].__len__() # take the length of the uinq as count for qeusion 7
    print('uniq', session['uniq'])
    print('uniq number', session['count_q7'])
    print('q_count', session['q_count'])
    # print('uniq:',uniq)
    qusion7 = ' '
    for row in session['uniq']: # check the pre-certificate to genarete the 7th question
        if row != 'NULL': # if the value not null
            qusion7 += str(session['q_count']) + '-' + row + '</br>' # gether all in this varibele
        if row == 'NULL': # if null just append in accepted session
            session['accepted_c'].append(row)
        session['q_count'] = session['q_count'] + 1
        session['count_q7'] = session['count_q7'] - 1
    #todo print
    print('q_count after', session['q_count'])
    print('count_7', session['count_q7'])
    # print(qusion7)
    if qusion7.strip(): # if not null
        q7 = 'Do you have any certificates from this list?</br>' + qusion7 + 'Please enter all <b>numbers</b> for certificates you have.'
    else:
        q7 = 'Are you ready to see the result.'

    return q7


# insert the result in result table
def uploadResult(data):
    cursor.execute("INSERT INTO result (b_id, certificate, vendor, exam, link) VALUES (?, ?, ?, ?, ?)", data)
    connection.commit()


# insert the whole conversation in CA table
def uploadCA(data):
    cursor.execute("INSERT INTO CA (question, answer, b_id, complete_chat, response) VALUES (?, ?, ?, ?,?)", data)
    connection.commit()


# ________

@app.route('/get')
# this function is a connection between the html interface and python code
def get_bot_response():

    counter = session['counter'] # =0
    userText = request.args.get('msg') # take the input for interface
    getinput(userText) # call it to pass the input
    getQuestion() # get the question form database

    if counter < 6:
        question()
    elif session['counter'] == 6: # if user finish anwser the six quesion
        q7_check_ans(session['uniq'])
        session['counter'] += 1
        print_result(session['accepted_c'], session['result_preC'], session['random_id'])
    elif session['counter'] > 6: # if program finish.
        session['res'] = 'If you want to try again reload this page <3'

    x = setinput() # pass the chat response to interface

    return str(x)
