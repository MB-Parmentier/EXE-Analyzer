

score_table = {
    "magic_number":10,
    "number_of_sections":0.5,
    "aslr":10,
    "e_lfanew":15,
    "flags":75,
    "pe_sign":10,
}

def check_magic_number(pe):
    mn = hex(pe.DOS_HEADER.e_magic)
    if mn != 0x5a4d:
        count=score_table["magic_number"]
        return count,"Le nombre magique est invalide (différent de MZ / 0x5a4d)."
    return 0

# Le "e_lfanew" pointe vers la table PE
# Il doit être plus petit que la taille du fichier
def check_e_lfanew(summary):
    eln = summary["DOS_Header"]["e_lfanew"]
    file_size = summary["File"]["Size"]
    eln = int(eln,16) # converti en base 10
    if eln > file_size:
        count=score_table["e_lfanew"]
        return count,"L'entête e_lfanew est invalide (plus grand que la taille du fichier)."
    return 0

def check_flags(summary):
    sec = []
    for s in summary["Sections"]:
        if "WRITE" in s["Flags"] and "EXECUTE" in s["Flags"]: # /!\ SECTION WRITE + EXECUTE
            sec.append(s["Name"])
    if len(sec)!=0:
        count=score_table["flags"]
        alert_string = "Au moins une section est à la fois en écriture et en exécution.\nSection(s) concernée(s) : "
        for name in sec:
            alert_string+="\n"+name
        print(alert_string)
        return count,alert_string
    return 0

def pe_sign(pe):
    eln = pe.NT_HEADERS.Signature
    eln = hex(eln)
    print(eln)
    if eln != 0x00004550:
        count=score_table["pe_sign"]
        return count,"La signature PE est invalide."
    print("C'est OK pour la signature")
    return 0

# ------------------------------------ LIST OF ALL FUNCTIONS / TOUTES LES FONCTIONS --------

check_list = [check_magic_number,pe_sign]
check_w_fsize = [check_e_lfanew,check_flags]

def main(sum):
    check_magic_number(sum)

if __name__ == "__main__":
    main()

