from .db import fetch, execute


async def db_check_jwt_user(user):
    query = """select * from users where username = :username"""
    values = {"username": user.username}
    result = await fetch(query, False, values)
    if result is None:
        return None
    else:
        return result


async def db_check_jwt_username(username):
    query = """select * from users where username = :username"""
    values = {"username": username}
    result = await fetch(query, True, values)
    if result is None:
        return False
    else:
        return True

async def db_insert_user(user):
    query = """insert into users(username, password, email, role, missions)
               values(:username, :password, :email, :role, :missions)"""
    values = dict(user)

    await execute(query, False, values)

async def db_select_missions():
    query = """select * from missions"""
    result = await fetch(query, False)
    return result

async def db_select_users_missions(username):
    query = """select * from missions_users where username = :username"""
    values = {"username":username}
    result = await fetch(query, False, values)
    return result