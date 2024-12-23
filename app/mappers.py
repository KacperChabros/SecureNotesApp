from note_service import clean_displayed_content

def get_login_attempts_dict(rows):
    login_attempts_dict  = [
            {"time": row['time'], "ipAddress": row['ipAddress']}
            for row in rows
        ]
    return login_attempts_dict
    
def get_notes_dict_list(rows):
    notes_dict_list = [
        {"id": row['noteId'], "userId": row['userId'], "title": clean_displayed_content(row['title'])}
        for row in rows
    ]
    return notes_dict_list

def get_note_dict(row):
    note_dict = {
        "id": row['noteId'],
        "owner_username": clean_displayed_content(row['owner_username']),
        "shared_to_username": clean_displayed_content(row['shared_to_username']),
        "title": clean_displayed_content(row['title']),
        "content": row['content'],
        "isCiphered": row['isCiphered'],
        "isPublic": row['isPublic'],
        "isShared": row['isShared'],
    }
    return note_dict