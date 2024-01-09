Create a Python 3.10 environment and activate it. Install the required libraries by executing the following command in the terminal, assuming the "backend/requirement.txt" file contains the necessary dependencies:

`pip install -r requirement.txt`

Once the libraries are installed, go to the "backend/roleplay_chatbot/" directory. Run the following commands to perform database migrations:

`python manage.py makemigrations`
`python manage.py migrate`

Finally, launch the project by running:
`python manage.py runserver`