import re

def passchk(memo,password):
    """
    パスワードがメモに含まれていたらTrue 含まれなかったらFalse
    """
    pattern = re.escape(password) 
    if re.search(pattern, memo):
        return True
    else:
        return False
