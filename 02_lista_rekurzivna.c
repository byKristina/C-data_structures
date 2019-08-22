/* Cilj ovog koda je da demonstrira funkcije za rad sa listama 
 * koje su ovaj put rekurzivne.
 * 
 * NAPOMENA: 
 * Jednostruko povezana lista je struktura podataka 
 * koja se sastoji od sekvence cvorova. Svaki cvor sadrzi 
 * podatke (odredjenog tipa) i pokazivac na sledeci cvor u
 * sekvenci. Prvi cvor u sekvenci naziva se glava liste. Ostatak
 * liste (bez glave) je takodje lista, i naziva se rep liste.
 * 
 * Definicija liste je rekurzivna i prirodno se mogu funkcije za
 * obradu listi pisati rekurzivno.
 **/


#include <stdio.h>
#include <stdlib.h>

/* Struktura koja predstavlja cvor liste */
typedef struct cvor {
    int vrednost;               /* podatak koji cvor sadrzi */
    struct cvor *sledeci;   /* pokazivac na sledeci cvor */
} Cvor;


/* Pomocna funkcija koja kreira cvor. Funkcija vrednost
 * novog cvora inicijalizuje na broj, dok pokazivac na
 * sledeci cvor u novom cvoru postavlja na NULL. 
 * Funkcija vraca pokazivac na novokreirani cvor ili NULL
 * ako alokacija nije uspesno izvrsena.
 */
Cvor *napravi_cvor(int broj)
{
    Cvor *novi = (Cvor *) malloc(sizeof(Cvor));
    if(novi == NULL)
        return NULL;

    novi->vrednost = broj;
    novi->sledeci = NULL;
    return novi;
}

/* Funkcija oslobadja dinamicku memoriju zauzetu za elemente liste 
 * ciji se pocetni cvor nalazi na adresi *adresa_glave. */
void oslobodi_listu(Cvor ** adresa_glave) 
{
    /* lista je prazna */
    if( *adresa_glave == NULL )
        return;

    /* Ako lista nije prazna, onda ima memorije koju treba osloboditi */
    /* pre nego oslobodimo memoriju za glavu liste, 
     * moramo osloboditi rep liste. */    
    oslobodi_listu( &(*adresa_glave)->sledeci); 
    /* nakon oslobodjenog repa, oslobadjamo i glavu*/
    free(*adresa_glave);
    /* azuriramo glavu u pozivajucoj funkciji tako da odgovara praznoj listi */
    *adresa_glave = NULL;
}


/* Funkcija dodaje novi cvor na pocetak liste. 
 * Kreira novi cvor koriscenjem funkcije napravi_cvor() i uvezuje ga na pocetak */
int dodaj_na_pocetak_liste(Cvor ** adresa_glave, int broj)
{
    /* Kreiramo nov cvor i proverimo da li je bilo greske pri alokaciji */
    Cvor *novi = napravi_cvor(broj); 
    if( novi == NULL)
        return 1;   /* informacija da je bilo greske pri alokaciji i da nista nije dodato u listu*/
    
    /* uvezujemo novi cvor na pocetak */
    novi->sledeci = *adresa_glave;
    *adresa_glave = novi;    /* Nov cvor je sada nova glava liste */
    return 0; 
}

/* Funkcija pronalazi i vraca pokazivac na poslednji element liste, 
 * ili NULL kao je lista prazna */
Cvor* pronadji_poslednji (Cvor* glava) 
{
    /* ako je lista prazna, nema ni poslednjeg cvor i u tom slucaju vracamo NULL.*/
    if( glava == NULL)
        return NULL;
    
    /* Ako je glava liste takva da nema sledeceg, onda je ona poslednji element */
    if( glava -> sledeci )
        return glava;
    
    /* Ako nista od prethodnog ne vazi, trazimo poslednjeg u repu liste. */
    return pronadji_poslednji(glava->sledeci);
}


/* Funkcija dodaje novi cvor na kraj liste.
 * Prilikom dodavanja u listu na kraj u velikoj vecini slucajeva nov broj se dodaje 
 * u rep liste u rekurzivnom pozivu.  
 * U slucaju da je u rekurzivnom pozivu doslo do greske pri alokaciji,
 * funkcija vraca 1 visem rekurzivnom pozivu koji tu informaciju vraca u rekurzivni poziv iznad,
 * sve dok se ne stigne u main(). Ako je funkcija vratila 0 onda nije bilo greske.
 * Tek iz main-a je moguce pristupiti pravom pocetku liste i osloboditi je celu.  
*/
int dodaj_na_kraj_liste(Cvor ** adresa_glave, int broj) 
{
    /* slucaj prazne liste  */
    if (*adresa_glave == NULL) {
         /*  Glava nove liste upravo novi cvor i ujedno i cela lista.  */
        Cvor *novi = napravi_cvor(broj);
        /* Proveravamo da li je doslo do greske prilikom alokacije memorije */
        if( novi == NULL)
            return 1;   /* informacija da je bilo greske pri alokaciji i da nista nije dodato u listu*/
        
        /*Azuriramo vrednost na koju pokazuje adresa_glave i tako azuriramo 
         * i pokazivacku promenljivu u pozivajucoj funkciji. */
        *adresa_glave = novi; 
        return 0;   /* vracamo se iz funkcije */
    }

    /* Ako lista nije prazna, nov element se dodaje u rep liste 
     * rekurzivan poziv ce napraviti nov element uvezati ga na kraj
     * i nama azurirati pokazivac na rep
     *
     *Vracamo povratnu vrednost rekurzivnog poziva, pa ako se u njemu dogodila greska 
     *tu inforamciju cemo vratiti pozivajucoj funkciji. 
     */
    return  dodaj_na_kraj_liste(&(*adresa_glave)->sledeci, broj);
}


/* Funkcija dodaje novi element u rastuce sortiranu listu tako da nova lista ostane sortirana.
 * Vraca 0 ako je alokacija novog cvora prosla bez greske, inace vraca 1 da bi se ta vrednost 
 * propagirala nazad do prvog poziva.
 */
int  dodaj_sortirano(Cvor ** adresa_glave, int broj) 
{
    /* Ako je polazna lista prazna ili je broj koji dodajemo manji od elementa u glavi liste, 
     * onda se u sustini element dodaje na pocetak liste */
    /* u slucaju prazne liste adresa_glave nove liste je upravo novi cvor */
    if (*adresa_glave == NULL) 
    {
        Cvor *novi = napravi_cvor(broj);
        /* Proveravamo da li je doslo do greske prilikom alokacije memorije */
         if( novi == NULL)
            return 1;   /* informacija da je bilo greske pri alokaciji i da nista nije dodato u listu*/
            
        *adresa_glave = novi;
        return 0 ;
    }

    /* Lista nije prazna*/
    /* Ako je broj manji ili jednak vrednosti u glavi liste, onda dodajemo na pocetak liste  */
    if ((*adresa_glave)->vrednost >= broj ) 
    {
        return dodaj_na_pocetak_liste(adresa_glave, broj);   /* vracamo informaciju o uspesnosti alokacije */ 
    }
    
    /* Inace, element treba dodati u rep, tako da rep i sa novim elementom
     * bude sortirana lista */
    return dodaj_sortirano(&(*adresa_glave)->sledeci, broj);
}


/* Funkcija trazi u listi element cija je vrednost jednaka datom broju. 
 * Vraca pokazivac na cvor liste u kome je sadrzan trazeni broj 
 * ili NULL u slucaju da takav element ne postoji u listi */
Cvor *pretrazi_listu(Cvor * glava, int broj) 
{
    /* U praznoj listi ga sigurno nema */
    if(glava == NULL )
        return NULL;
  
    /* ako glava liste bas sadrzi trazeni broj */
    if(glava->vrednost == broj )
        return glava; 

    /* Ako nije nijedna od prethodnih situacija, pretragu nastavljamo u repu */
    return pretrazi_listu(glava->sledeci, broj);
}


void ispisi_listu(Cvor * glava);


/* Funkcija brise iz liste sve cvorove koji sadrze dati broj.
   Funkcija azurira pokazivac na glavu liste (koji moze biti 
   promenjen u slucaju da se obrise stara glava) */
void obrisi_element(Cvor ** adresa_glave, int broj) 
{
    /* Ako je lista prazna nema sta da se brise, vracamo se iz funkcije. */
    if( *adresa_glave == NULL)
        return ;

    /* Pre nego proverimo situaciju sa glavom liste, obrisacemo sve
     cvororve iz repa koji imaju vrednost bas broj */
    obrisi_element(&(*adresa_glave)->sledeci, broj);
    
    /* Preostaje da proverimo da li glavu treba obrisati. */
    if ( (*adresa_glave)->vrednost == broj ) 
    {
        Cvor* pomocni = *adresa_glave; /* Cvor koji treba da se obrise*/
        *adresa_glave = (*adresa_glave)->sledeci; /* azuriramo pokazivac glava da pokazuje na sledeci u listi. */
        free(pomocni); /* brisemo element koji je do malocas bio glava liste. */
    }
    /* Sada nam je lista sredjena i vracamo se iz funkcije. */
}

/* Funkcija ispisuje samo elemente liste razdvojene zapetama */
void ispisi_elemente(Cvor *glava) 
{
    /* Prazna lista*/
    if(glava == NULL)  
        return;
    
    /* Ispisujemo element u glavi liste*/
    printf(" %d",glava->vrednost); 
    /* Rekurzivni poziv za ispis svega ostalo */
    ispisi_elemente(glava->sledeci);  
}


/* Funkcija prikazuje elemente liste pocev od glave ka kraju liste.
 * Ne saljemo joj adresu promenljive koja cuva glavu liste, jer 
 * ova funkcija nece menjati listu, pa nema ni potrebe da azuriza pokazivac
 * iz pozivajuce funkcije. */
void ispisi_listu(Cvor * glava)
{
    putchar('[');
    ispisi_elemente(glava);
    putchar(']');

    putchar('\n');
}




/* Glavni program u kome testiramo sve funkcije za rad sa listama */
int main() 
{
    Cvor *glava = NULL;  /* na pocetku imamo praznu listu */
    Cvor *trazeni = NULL;
    int broj;

    /* Testiramo dodavanje na pocetak*/
    printf("\n----Unosimo elemente na pocetak liste! (za kraj unesite EOF tj. CTRL+D )----\n");
    while(scanf("%d",&broj)>0)
    { /* Ako je funkcija vratila 1 onda je bilo greske pri alokaciji memorije za nov cvor 
        i prethodno alociranu listu moramo osloboditi pre napustanja programa.  */
        if ( dodaj_na_pocetak_liste(&glava, broj) == 1) 
        {
            fprintf(stderr, "Neuspesna alokacija za nov cvor za broj %d\n",broj);
            oslobodi_listu(&glava);
            exit(EXIT_FAILURE);
        }
        printf("\n\tLista: ");
        ispisi_listu(glava);
    }

    ispisi_listu(glava);

    printf("\nUnesite element koji se trazi u listi: ");
    scanf("%d", &broj);

    trazeni=pretrazi_listu(glava, broj);
    if( trazeni == NULL)
        printf("Element NIJE u listi!\n");
    else
        printf("Trazeni broj %d je u listi!\n", trazeni->vrednost);

    oslobodi_listu(&glava);


    /* DODAVANJE NA KRAJ*/

    printf("\n----Unosimo elemente na kraj liste! (za kraj unesite EOF tj. CTRL+D )----\n");
    while(scanf("%d",&broj)>0) 
    { /* Ako je funkcija vratila 1 onda je bilo greske pri alokaciji memorije za nov cvor 
        i prethodno alociranu listu moramo osloboditi pre napustanja programa. Jedino iz main() funkcije 
        nam je dostupna adresa prvog cvora liste i jedino iz main() funkcije mozemo osloboditi listu. */
         if ( dodaj_na_kraj_liste(&glava, broj) == 1) 
        {
            fprintf(stderr, "Neuspesna alokacija za nov cvor za broj %d\n",broj);
            oslobodi_listu(&glava);
            exit(EXIT_FAILURE);
        }
        
        printf("\n\tLista: ");
        ispisi_listu(glava);
    }

    ispisi_listu(glava);

    /* brisemo elemente iz liste cije polje vrednost je jednako broju procitanog 
    sa ulaza*/
    printf("\nUnesite element koji se brise u listi: ");
    scanf("%d", &broj);

    obrisi_element(&glava, broj);

    printf("Lista nakon brisanja:  ");
    ispisi_listu(glava);

    oslobodi_listu(&glava);

    /* Dodajemo u listu, a da pri tom lista bude sortirana u neopadajucem 
    poretku */
    printf("\n----Unosimo elemente tako da lista bude sortirana! (za kraj unesite EOF tj. CTRL+D )----\n");

    while(scanf("%d",&broj)>0) 
    {
         /* Ako je funkcija vratila 1 onda je bilo greske pri alokaciji memorije za nov cvor 
        i prethodno alociranu listu moramo osloboditi pre napustanja programa. Jedino iz main() funkcije 
        nam je dostupna adresa prvog cvora liste i jedino iz main() funkcije mozemo osloboditi listu. */
        if ( dodaj_sortirano(&glava, broj) == 1) 
        {
            fprintf(stderr, "Neuspesna alokacija za nov cvor za broj %d\n",broj);
            oslobodi_listu(&glava);
            exit(EXIT_FAILURE);
        }
        
        printf("\n\tLista: ");
        ispisi_listu(glava);
    }
    
    printf("\n Sortirana lista: ");
    ispisi_listu(glava);

    oslobodi_listu(&glava);

    return 0;
}