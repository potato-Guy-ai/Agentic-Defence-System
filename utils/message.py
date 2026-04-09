def create_message(sender, data, priority="low"):
    return {
        "sender": sender,
        "priority": priority,
        "data": data
    }