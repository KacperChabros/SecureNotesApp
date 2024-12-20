
def get_login_attempts_dict(rows):
    login_attempts_dict  = [
            {"time": row['time'], "ipAddress": row['ipAddress']}
            for row in rows
        ]
    return login_attempts_dict
    
def get_notes_dict_list(rows):
    notes_dict_list = [
        {"id": row['noteId'], "userId": row['userId'], "title": row['title']}
        for row in rows
    ]
    return notes_dict_list