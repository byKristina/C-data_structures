/*  U ovom programu testiramo rad sa dvostruko povezanim listama.
 * Prikazujemo osnovne funkcije za rad sa listama, koje smo vec upoznali na
 * jednostruko povezanim listama.
 * Za razliku od jednostruko povezane liste, cvor dvostruko povezane liste 
 * pored podataka koje sadrzi, sadrzi i pokazivac na sledeci i na prethodni element liste.
 * Time nam je omoguceno da se kroz dvostruko povezanu listu krecemo
 * i od pocetka ka kraju (sto smo mogli i sa jednostruko povezanom listom)
 * i od kraja ka pocetku, jer imamo u svakom cvoru pokazivac na prethodni.
 **/

#include <stdio.h>
#include <stdlib.h>

/* struktura kojom je predstavljen svaki element liste */
typedef struct cvor{
    int vrednost;
    struct cvor *sledeci;
    struct cvor *prethodni;
} Cvor;

/* Pomocna funkcija koja kreira cvor. Funkcija vrednost
 * novog cvora inicijalizuje na broj, dok pokazivac na
 * sledeci cvor u novom cvoru postavlja na NULL. 
 * Funkcija vraca pokazivac na novokreirani cvor ili NULL
 * ako alokacija nije uspesno izvrsena.  */
Cvor* napravi_cvor(int broj) {
    Cvor* novi  = (Cvor*)malloc(sizeof(Cvor));
    if(novi == NULL)
        return NULL;

    /* inicijalizacija polja u novom cvoru */
    novi->vrednost = broj;
    novi->sledeci = NULL;
    novi->prethodni = NULL;
    return novi;
}

/* Funkcija oslobadja dinamicku memoriju zauzetu za elemente liste 
 * ciji se pocetni cvor nalazi na adresi *glava. */
void oslobodi_listu(Cvor ** adresa_glave) {
    Cvor *pomocni = NULL;

    /* Ako lista nije prazna, onda ima memorije koju treba osloboditi */
    while (*adresa_glave != NULL) {
        /* moramo najpre zapamtiti adresu sledeceg elementa, a tek 
         * onda osloboditi element koji predstavlja glavu liste */
        pomocni = (*adresa_glave)->sledeci;
        free(*adresa_glave);
        /* sledeci element je nova glava liste*/
        *adresa_glave = pomocni;
    }
}

/* Funkcija proverava uspesnost alokacije memorije za cvor novi i ukoliko 
 * alokacija nije bila uspesna, oslobadja se sva prethodno zauzeta memorija 
 * za listu cija pocetni cvor se nalazi na adresi adresa_glave.  */
void proveri_alokaciju(Cvor** adresa_glave, Cvor* novi) {
    /* Ukoliko je novi NULL */
    if ( novi == NULL ) {
        fprintf(stderr, "Neuspela alokacija za nov cvor\n");
        oslobodi_listu(adresa_glave);     /* oslobadjamo sve dinamicki alocirano */    
        exit(EXIT_FAILURE);
    }
}



/* Funkcija dodaje novi cvor na pocetak liste. 
 * Kreira novi cvor koriscenjem funkcije napravi_cvor() i uvezuje ga na pocetak */
void dodaj_na_pocetak_liste(Cvor** adresa_glave, int broj) {
   /* Kreiramo nov cvor i proverimo da li je bilo greske pri alokaciji */
    Cvor *novi = napravi_cvor(broj); 
    proveri_alokaciju(adresa_glave, novi);

    /* sledeci od novog cvora je glava stare liste */
    novi->sledeci = *adresa_glave;
    /* ako stara lista nije bila prazna, onda njena glava nije
        NULL i moramo postaviti da prethodni od glave bude nov cvor. */
    if( *adresa_glave != NULL)
        (*adresa_glave)->prethodni=novi;
    /* azuriramo pokazivac na glavu u pozivajucoj funkciji jer je novi od sada glava liste */
    *adresa_glave =novi;
}



/* Funkcija pronalazi i vraca pokazivac na poslednji element liste, 
 * ili NULL kao je lista prazna */
Cvor* pronadji_poslednji (Cvor* glava) {
    /* ako je lista prazna, nema ni poslednjeg cvor i u tom slucaju vracamo NULL.*/
    if( glava == NULL)
        return NULL;
    
    /* Sve dok glava ne pokazije na cvor koji nema sledeceg, pomeramo pokazivac
     * glava na taj sledeci element. Kada izadjemo iz petlje, glava ce pokazivati na element liste
     * koji nema sledeceg, tj, poslednji element liste je. Zato vracamo vrednost pokazivaca glava.
     * 
     * glava je argument funkcije i njegove promene nece se odraziti na vrednost pokazivaca glava 
     * u pozivajucoj funkciji.
     */
    while (glava->sledeci != NULL)
        glava = glava->sledeci;
    
    return glava;
}


/* Funkcija nov cvor dodaje na kraj liste.  */
void dodaj_na_kraj_liste( Cvor** adresa_glave, int broj) {
     Cvor *novi = napravi_cvor(broj);
    /* Proveravamo da li je doslo do greske prilikom alokacije memorije */
    proveri_alokaciju(adresa_glave, novi);

    /* ako je lista u koju dodajemo prazna. Nov cvor je jedini cvor u novoj listi  
     *i time je i glava nove liste. */
    if( *adresa_glave == NULL) {
        *adresa_glave = novi;
        return;
    }
  
    /* Ako lista nije prazna, pronalazimo poslednji element liste */
    Cvor* poslednji = pronadji_poslednji(*adresa_glave);

    /* tada uvezujemo nov cvor na kraj, tako sto mu azuriramo pokazivac na prethodni 
     *da pokazuje na poslednjeg. Sledeci od poslednjeg treba da bude nov cvor.*/
    poslednji->sledeci = novi;
    novi->prethodni = poslednji;  
}

/* Pomocna funkcija pronalazi cvor u listi iza koga treba umetnuti nov element sa vrednoscu broj .*/
Cvor * pronadji_mesto_umetanja(Cvor* glava, int broj ) {
    /*Ako je lista prazna onda nema takvog mesta i vracamo NULL */
    if(glava == NULL)
        return NULL;
    
    /* Krecemo se kroz listu sve dok se ne dodje do elementa 
     * ciji je sledeci element veci ili jednak od novog elementa, 
     * ili dok se ne dodje do poslednjeg elementa.
     * 
     * Zbog lenjog izracunavanja izraza u C-u prvi deo konjukcije 
     * mora biti provera da li smo dosli do poslednjeg elementa liste
     * pre nego sto proverimo vrednost njegovog sledeceg elementa,
     * jer u slucaju poslednjeg, sledeci ne postoji, pa ni vrednost.*/
    while (glava->sledeci != NULL  && glava->sledeci->vrednost < broj) 
        glava = glava->sledeci;
    
    /* Iz petlje smo mogli izaci jer smo dosli do poslednjeg elementa ili smo se zaustavili ranije 
     * na elementu ciji sledeci ima vrednost vecu od broj */
    return glava;
}


void dodaj_iza(Cvor* tekuci, Cvor* novi) { 
    /* Novi element dodajemo IZA tekuceg elementa */
    novi->sledeci = tekuci->sledeci;
    novi->prethodni = tekuci;

    /* Ako tekuci ima sledeceg, onda upravo dodajemo njemu prethodnika i potrebno je i njemu 
     * da postavimo pokazivace na ispravne adrese */
    if( tekuci->sledeci != NULL )
        tekuci->sledeci->prethodni = novi;
    tekuci->sledeci = novi;
}



/* Fukcija dodaje u listu nov cvor na odgovarajuce mesto. Tj. Funkcija pronalazi
   odgovarajuci cvor u listi iza kod treba uvezati nov cvor. */
void dodaj_sortirano(Cvor** adresa_glave, int broj) {
    /* u slucaju prazne liste glava nove liste je upravo novi cvor */
    if (*adresa_glave == NULL) {
        Cvor *novi = napravi_cvor(broj);
        /* Proveravamo da li je doslo do greske prilikom alokacije memorije */
        proveri_alokaciju(adresa_glave, novi);
        *adresa_glave = novi;
        return;
    }
    
    /* Lista nije prazna*/	
    /* Ukoliko je vrednost glave liste veca od nove vrednosti onda nov 
    cvor treba da uvezati pre glave, tj. staviti na pocetak liste. */
    if ((*adresa_glave)->vrednost >= broj ) {
        dodaj_na_pocetak_liste(adresa_glave, broj);
        return;
    }
    
    Cvor *novi = napravi_cvor(broj);
    /* Proveravamo da li je doslo do greske prilikom alokacije memorije */
    proveri_alokaciju(adresa_glave, novi);
   
    Cvor *pomocni = pronadji_mesto_umetanja(*adresa_glave, broj);
    /* Uvezujemo novi cvor iza pomocnog */
    dodaj_iza(pomocni, novi);
}

/* Fukcija prolazi kroz listu od glave do kraja liste u potrazi za 
   cvorom koji na polju vrednost ima trazenu vrednost broj. */
Cvor* pretrazi_listu(Cvor* glava, int broj) {
    for( ; glava!=NULL; glava = glava->sledeci)
        if( glava->vrednost == broj)	/* nasli smo cvor sa trazenom vrednoscu i vracamo pokazivac na njega. */
            return glava;
  
    /* dosli smo do kraja liste i nismo nasli trazeni element. pa vracamo NULL. */
    return NULL;
}

/* Funkcija brise u listi na koju pokazuje pokazivac glava bas 
  onaj cvor na koji pokazuje pokazivac tekuci. Obratiti paznju da je kod dvostruke
  liste ovo mnogo lakse uraditi jer cvor tekuci sadrzi pokazivace na svog sledbenika
  i prethodnika u listi. Pre nego sto fizicki obrisemo tekuci obavezno moramo azurirati
  sve pokazivace sledbenika i prethodnika.   */
void obrisi_tekuci(Cvor** adresa_glave, Cvor* tekuci)  {
    /* ako je tekuci NULL pokazivac nema sta da se brise. */
    if(tekuci == NULL)
        return;
        
    /* Ako postoji prethodnik od tekuceg onda se postavlja da njegov sledeci bude sledeci od tekuceg */
    if( tekuci->prethodni != NULL)
        tekuci->prethodni->sledeci = tekuci->sledeci;

    /* Ako postoji sledbenik tekuceg (cvora koji bismo obrisali) onda njegov prethodnik treba da bude prethodnik od tekuceg  */
    if(tekuci->sledeci != NULL)
        tekuci->sledeci->prethodni = tekuci->prethodni;

    /* ako je glava element koji se brise. 
     * Glava nove liste ce biti sledbenik od glave. */	
    if( tekuci == *adresa_glave)
        *adresa_glave =  tekuci->sledeci;

    /* oslobadjamo dinamicki alociran prostor za cvor tekuci*/ 
    free(tekuci);
}


/* Brisemo element u listi cije polje vrednost je trazeni broj */
void obrisi_element(Cvor** adresa_glave, int broj) {
    Cvor* tekuci = *adresa_glave;

    while((tekuci = pretrazi_listu(*adresa_glave,broj)) != NULL)   {
        obrisi_tekuci(adresa_glave, tekuci);   /* obrisacemo tekuci */
    }
}


/* Funkcija ispisuje vrednosti iz liste. */
void ispisi_listu(Cvor* glava)  {
    putchar('[');
    for( ;glava != NULL; glava = glava->sledeci)
        printf("%d ",glava->vrednost);
    putchar(']');
    putchar('\n');
}


/* Funkcija prikazuje elemente liste pocev od kraja ka glavi liste.
  Kod dvostruko povezane to je jako jednostavno jer svaki cvor 
  ima pokazivac na prethodni element u listi. */
void ispisi_listu_u_nazad(Cvor* glava) {
    putchar('[');
    if(glava == NULL ) {
        printf("]\n");
        return;
    }
    
    glava = pronadji_poslednji(glava);
  
    /* ispisujemo element po element liste unazad. Pristupamo elementu liste i
        nakon ispisa pomeramo pokazivac glava da pokazuje na prethodnika */
    for( ;glava != NULL; glava = glava->prethodni)
        printf("%d ", glava->vrednost);
  
    printf("]\n");
}


/* Glavni program u kome testiramo sve funkcije za rad sa listama */
int main() {
    Cvor *glava = NULL;  /* na pocetku imamo praznu listu */
    Cvor *trazeni = NULL;
    int broj;

    /* Testiramo dodavanje na pocetak*/
    printf("\n----Unosimo elemente na pocetak liste! (za kraj unesite EOF tj. CTRL+D )----\n");
    while(scanf("%d",&broj)>0)
    {
        dodaj_na_pocetak_liste(&glava, broj);
        printf("\n\tLista: ");
        ispisi_listu(glava);
    }

    ispisi_listu(glava);
    printf("\nLista ispisana u nazad: ");
    ispisi_listu_u_nazad(glava);

    printf("\nUnesite element koji se trazi u listi: ");
    scanf("%d", &broj);

    trazeni=pretrazi_listu(glava, broj);
    if(trazeni==NULL)
        printf("Element NIJE u listi!\n");
    else
        printf("Trazeni broj %d je u listi!\n", trazeni->vrednost);

    oslobodi_listu(&glava);


    /* DODAVANJE NA KRAJ*/

    printf("\n----Unosimo elemente na kraj liste! (za kraj unesite EOF tj. CTRL+D )----\n");
    while(scanf("%d",&broj)>0) {
        dodaj_na_kraj_liste(&glava, broj);
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

    while(scanf("%d",&broj)>0) {
        dodaj_sortirano(&glava, broj);
        printf("\n\tLista: ");
        ispisi_listu(glava);
    }
    
    printf("\n Sortirana lista: ");
    ispisi_listu(glava);

    oslobodi_listu(&glava);

    return 0;
}

