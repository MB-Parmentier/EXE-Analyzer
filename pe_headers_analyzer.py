

score_table = {
    "magic_number":10,
    "number_of_sections":0.5,
    "aslr":10,
    "e_lfanew":15
}

def check_magic_number(sum):
    mn = sum["DOS_Header"]["e_magic"]
    if mn != 0x5a4d:
        count=score_table["magic_number"]
        return count,"Le nombre magique est invalide (différent de MZ / 0x5a4d)."
    return 0

# Le "e_lfanew" pointe vers la table PE
# Il doit être plus petit que la taille du fichier
def check_e_lfanew(sum):
    eln = sum["DOS_Header"]["e_lfanew"]
    file_size = sum["File"]["Size"]
    eln = int(eln,16) # converti en base 10
    if eln > file_size:
        count=score_table["e_lfanew"]
        return count,"L'entête e_lfanew est invalide (plus grand que la taille du fichier)."
    return 0

def check_flags(sum):
    return 0

# ------------------------------------ LIST OF ALL FUNCTIONS / TOUTES LES FONCTIONS --------

check_list = [check_magic_number,check_e_lfanew]

def main(sum):
    check_magic_number(sum)

if __name__ == "__main__":
    main()

