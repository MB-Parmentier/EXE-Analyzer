

score_table = {
    "magic_number":10,
    "number_of_sections":0.5,
    "aslr":10,
    "e_lfanew":15
}

def check_magic_number(sum):
    print(sum["DOS_Header"]["e_magic"])
    if sum["DOS_Header"]["e_magic"] != 0x5a4d:
        count=score_table["magic_number"]
        return count,"Le nombre magique est invalide (différent de 0x5a4d)."
    return 0

def check_flags(sum):
    return 0

# ------------------------------------ LIST OF ALL FUNCTIONS / TOUTES LES FONCTIONS --------

check_list = [check_magic_number]

def main(sum):
    check_magic_number(sum)

if __name__ == "__main__":
    main()

