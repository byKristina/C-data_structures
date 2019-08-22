/*Program implementira funkcije za rad sa binarnim pretrazivackim stablom celih brojeva*/

/* NAPOMENA: Binarno stablo je dinamicka stuktura podataka u kojoj svaki cvor 
 * pored podataka sadrzi i 2 pokazivaca na levog i desnog potomka.  Svako stablo ima cvor koren.
 * Ostali cvorovi u stablu su potomci korena. Koren kao i svi ostali cvorovi u stablu imaju dva, levo
 * i desno podstablo. Oni cvorovi koji nemaju svoje potomke nazivaju se listovima.
 * 
 * Stablo je pretrazivacko ukoliko za podatke u cvorovima u levom podstablu vazi da su po nekom 
 * kriterijumu manji od vrednosti podatka u korenu, i analogno u desnom podstablu svi cvorovi imaju
 * vecu vrednost od one u korenu.
 */

#include <stdio.h>
#include <stdlib.h>

/* struktura kojom se predstavlja cvor drveta */
typedef struct dcvor{
    int broj;
    struct dcvor* levo, *desno;
} Cvor;

/* Funkcija alocira prostor za novi cvor drveta, inicijalizuje polja
    strukture i vraca pokazivac na nov cvor */
Cvor* napravi_cvor(int b ) {  
    Cvor* novi = (Cvor*) malloc(sizeof(Cvor));
    if( novi == NULL)
        return NULL;

    /* Inicijalizacija polja novog cvora */
    novi->broj = b;
    novi->levo = NULL;
    novi->desno = NULL;
    
    return novi;
}


/* Oslobadjamo dinamicki alociran prostor za stablo
 * Nakon oslobadjanja se u pozivajucoj funkciji koren 
 * postavljana NULL, jer je stablo prazno  */
void oslobodi_stablo(Cvor** adresa_korena)  {
      /* Prazno stablo i nema sta da se oslobadja */
    if( *adresa_korena == NULL)
        return;
    
    /* rekurzivno oslobadjamo najpre levo, a onda i desno podstablo*/
    if( (*adresa_korena)->levo ) 
        oslobodi_stablo(&(*adresa_korena)->levo);
    if( (*adresa_korena)->desno) 
        oslobodi_stablo(&(*adresa_korena)->desno);
    
    free(*adresa_korena);
    *adresa_korena =NULL;
}


/* Funkcija dodaje nov cvor u stablo i 
 * azurira vrednost korena stabla u pozivajucoj funkciji.
 * Ukoliko je neuspesna alokacija memorije za nov cvor 
 * vraca se 
 */
int dodaj_u_stablo(Cvor** adresa_korena, int broj) {
    /* postojece stablo je prazno*/
    if( *adresa_korena == NULL){ 
        Cvor* novi = napravi_cvor(broj);
        if( novi == NULL )
            return 1;    /* Dogodila se greska pri alokaciji */
        
        *adresa_korena = novi;  /* novi ce biti od sada koren stabla*/
        return 0 ;
    }
        
    /* Brojeve smestamo u uredjeno binarno stablo, pa 
     * ako je broj koji ubacujemo manji od broja koji je u korenu  
     *
     * Ako se dogodila greska pri alokaciji u nekom od rekurzivnih poziva, vracamo tu vrednost.  */
    if( broj < (*adresa_korena)->broj)         /* dodajemo u levo podstablo */
        return dodaj_u_stablo(&(*adresa_korena)->levo, broj);
    /* ako je broj manji ili jednak od broja koji je u korenu stabla, dodajemo nov cvor desno od korena */
    else 
        return dodaj_u_stablo(&(*adresa_korena)->desno, broj);
    
    return 0;
}


/* Funkcija trazi ceo broj u stablu, ako ga nadje vraca pokazivac na cvor sa trazenim brojem.
 * Ukoliko ne nadje vraca NULL pokazivac. */
Cvor* pretrazi_stablo(Cvor* koren, int n) {
    /* U praznom stablu ga nema*/
    if(koren == NULL)
        return NULL;
    
    /* Nadjen je*/
    if(koren->broj == n)
        return koren;
    /* U zavisnosti od vrednosti u korenu, znamo da li da ga trazimo u levom ili desnom podstablu */
    if( koren->broj > n)
        return pretrazi_stablo(koren->levo, n);
    else 
        return pretrazi_stablo(koren->desno, n);
}


/* Funkcija nalazi najmanji element u binarnom stablu pretrage. 
 * Vraca pokazivac na cvor sa najvecim brojem. U slucaju neuspeha i praznog stabla vraca NULL. */
Cvor* pronadji_najmanji(Cvor* koren) {
    /* Nema ga u praznom stablu */
    if(koren == NULL)
        return NULL;
    
    /* Manji od korena se nalaze u levom podstablu, ali ako je levo podstablo prazno,
     * onda od korena nema manjeg */
    if(koren->levo == NULL)
        return koren;
    /* Inace, nastavljamo da ga trazimo u levom podstablu */
    return pronadji_najmanji(koren->levo);
}



/* Funkcija nalazi najveci element u binarnom stablu pretrage. 
    Vraca pokazivac na cvor sa najvecim brojem. U slucaju neuspeha i praznog stabla vraca NULL. */
Cvor* pronadji_najveci(Cvor* koren) {
    /* Nema ga u praznom stablu */
    if(koren == NULL)
        return NULL;
    
    /* Veci od korena se nalaze u desnom podstablu, ali ako je desno podstablo prazno,
     * onda od korena nema veceg */
    if(koren->desno == NULL)
        return koren;
    
    /*Inace, veci se nalazi u desnom podstabu i  pretragu moramo nastaviti tamo */
    return pronadji_najveci(koren->desno);
}


/* Funkcija brise element iz stabla ciji je broj upravo jednak broju n. 
    Funkcija azurira koren stabla u pozivajucoj funkciji, jer u ovoj funkciji 
    koren moze biti promenjen u funkciji. */
void obrisi_element(Cvor** adresa_korena, int n) {
    Cvor *pomocni = NULL;

    /* Izlaz iz rekurzije: ako je stablo prazno,  nema sta da se brise  */
    if (*adresa_korena == NULL)
        return ;

    /* Ako je vrednost broja veca od vrednosti u korenu stablua,
       tada se broj eventualno nalazi u desnom podstablu,
       pa treba rekurzivno primeniti postupak na desno 
       podstablo. Koren ovako modifikovanog stabla je
       nepromenjen. */
    if ((*adresa_korena)->broj < n) {
        obrisi_element(&(*adresa_korena)->desno, n);
        return;
    }

    /* Ako je vrednost broja manja od vrednosti korena,
       tada se broj eventualno nalazi u levom podstablu,
       pa treba rekurzivno primeniti postupak na levo 
       podstablo. Koren ovako modifikovanog stabla je
       nepromenjen. */
    if ((*adresa_korena)->broj > n)  {
        obrisi_element(&(*adresa_korena)->levo, n);
        return ;
    }

    /* Slede podslucajevi vezani za slucaj kada je vrednost
       u korenu jednaka broju koji se brise (tj. slucaj kada 
       treba obrisati koren) */

    /* Ako koren nema sinova, tada se on prosto brise, i
       rezultat je prazno stablo (vracamo NULL) */
    if ((*adresa_korena)->levo == NULL && (*adresa_korena)->desno == NULL) {
        free(*adresa_korena);
        *adresa_korena = NULL;
        return;
    }

    /* Ako koren ima samo levog sina, tada se brisanje
       vrsi tako sto obrisemo koren, a novi koren postaje
       levi sin */
    if ((*adresa_korena)->levo != NULL && (*adresa_korena)->desno == NULL) { 
        pomocni = (*adresa_korena)->levo;
        free(*adresa_korena);
        *adresa_korena = pomocni;
        return;
    }

    /* Ako koren ima samo desnog sina, tada se brisanje 
       vrsi tako sto obrisemo koren, a novi koren postaje
       desni sin */
    if ((*adresa_korena)->desno != NULL && (*adresa_korena)->levo == NULL) {
        pomocni = (*adresa_korena)->desno;
        free(*adresa_korena);
        *adresa_korena =  pomocni;
        return;
    }

    /* Slucaj kada koren ima oba sina. 
       Tada se brisanje vrsi na sledeci nacin: 
       - najpre se potrazi sledbenik korena (u smislu poretka) u stablu. To
       je upravo po vrednosti najmanji cvor u desnom podstablu.
       On se moze pronaci npr. funkcijom pronadji_najmanji().
       - Nakon toga se u koren smesti vrednost tog cvora, a u taj
       cvor se smesti vrednost korena (tj. broj koji se brise).
       - Onda se prosto rekurzivno pozove funkcija za brisanje
       na desno podstablo. S obzirom da u njemu treba obrisati
       najmanji element, a on definitivno ima najvise jednog 
       potomka, jasno je da ce njegovo brisanje biti obavljeno na 
       jedan od jednostavnijih nacina koji su gore opisani. */
    pomocni = pronadji_najmanji((*adresa_korena)->desno);
    (*adresa_korena)->broj = pomocni->broj;
    pomocni->broj = n;
    obrisi_element(&(*adresa_korena)->desno, n);
}

/* Funkcija ispisuje stablo u infiksnoj notaciji ( Levo - Koren - Desno )*/
void ispisi_drvo_infixno(Cvor* koren) {
    if(koren != NULL) {
        ispisi_drvo_infixno(koren->levo);        /* Prvo ispisujemo sve cvorove levo od korena */
        printf("%d ", koren->broj);                 /* ispisujemo broj u korenu */
        ispisi_drvo_infixno(koren->desno);  /* Na kraju ispisujemo desno podstablo */
    }
}

/* Funkcija ispisuje stablo prefiksno  ( Koren - Levo - Desno )*/
void ispisi_drvo_prefixno(Cvor* koren) {
    if(koren != NULL) {
        printf("%d ", koren->broj);                 /* ispisujemo broj u korenu */
        ispisi_drvo_prefixno(koren->levo);      /* Prvo ispisujemo sve cvorove levo od korena */
        ispisi_drvo_prefixno(koren->desno);      /* Na kraju ispisujemo desno podstablo */
    }
}

/* Funkcija ispisuje stablo postfiksno  ( Levo - Desno - Koren)*/
void ispisi_drvo_postfixno(Cvor* koren){
    if(koren != NULL) {
        ispisi_drvo_postfixno(koren->levo);       /* Prvo ispisujemo sve cvorove levo od korena */
        ispisi_drvo_postfixno(koren->desno);        /* Na kraju ispisujemo desno podstablo */
        printf("%d ", koren->broj);                         /* ispisujemo broj u korenu */
    }
}

int main(){
    Cvor* koren = NULL; /* Napomena: Prazno stablo! */
    int n;
    Cvor* trazeni = NULL ;

    printf("Unosite cele brojeve! --- CTRL+D za prekid unosenja!\n");
    while( scanf("%d",&n) != EOF) {
        /* Dodajemo nov broj u stablo */
        if ( dodaj_u_stablo(&koren,n) == 1)
        {
            fprintf(stderr, "Neuspesna alokacija za nov cvor!\n");
            oslobodi_stablo(&koren);
            exit(EXIT_FAILURE);
        }            
        
        printf("    Stablo ( L-K-D) : ");
        
        ispisi_drvo_infixno(koren);
        putchar('\n');
    }
    
    printf("\nUneto drvo u infixnom obilasku (L-K-D): ");
    ispisi_drvo_infixno(koren);
    putchar('\n');

    printf("Uneto drvo u prefixnom obilasku (K-L-D): ");
    ispisi_drvo_prefixno(koren);
    putchar('\n');

    printf("Uneto drvo u postfixnom obilasku (L-D-K): ");
    ispisi_drvo_postfixno(koren);
    putchar('\n');

    printf("Koji se to broj trazi u stablu? \t");
    scanf("%d",&n);

    trazeni = pretrazi_stablo(koren,n);
    if(trazeni == NULL)
        printf("Element %d nije u stablu!\n",n);
    else 
        printf("Element %d se nalazi u stablu!!!\n", trazeni->broj);
        
    printf("\nNajveci element u stablu je %d, a najmanji je %d.\n", pronadji_najveci(koren)->broj , pronadji_najmanji(koren)->broj);

    oslobodi_stablo(&koren);
    return 0;
}
