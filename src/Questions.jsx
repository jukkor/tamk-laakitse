const questions = [
  {
    "category": "Lääkehoitoa ohjaavat lait ja asetukset",
    "question": "Tiedät tärkeimmät lääkehoidon säännöt ja ohjeet. Noudatat näitä sääntöjä ja ohjeita.",
    "additionalInformation": ""
  },
  {
    "category": "Lääkehoitoa ohjaavat lait ja asetukset",
    "question": "Tiedät Suomen viranomaiset, jotka ohjaavat ja valvovat lääkehoitoa Suomessa. Tiedät, mitä tehtäviä ja vastuita niillä on (STM, THL, FIMEA, KELA, VALVIRA, AVI).",
    "additionalInformation": "Viranomainen on henkilö tai paikka, joka edustaa ja käyttää julkista valtaa. Esimerkiksi poliisit, pelastustyöntekijät ja KELAn työntekijät  \novat viranomaisia. \n\n\nSTM\tSosiaali- ja terveysministeriö \nTHL\tTerveyden ja hyvinvoinnin laitos \nFIMEA\tLääkealan turvallisuus- ja kehittämiskeskus \nKELA\tKansaneläkelaitos  \nVALVIRA\tSosiaali- ja terveysalan lupa- ja valvontavirasto \nAVI\tAluehallintovirasto"
  },
  {
    "category": "Lääkehoitoprosessi ja lääkehoitosuunnitelma",
    "question": "Tiedät, mikä on lääkehoitoprosessi.",
    "additionalInformation": "Lääkehoitoprosessiin kuuluu monta vaihetta, kuten esimerkiksi lääkkeen määrääminen, lääkkeen antaminen ja lääkehoidon vaikutusten arviointi."
  },
  {
    "category": "Lääkehoitoprosessi ja lääkehoitosuunnitelma",
    "question": "Tiedät, mikä on lääkehoitosuunnitelma.",
    "additionalInformation": "Lääkehoitosuunnitelma on dokumentti, joka ohjaa lääkehoidon toteuttamista. Toimintayksiköllä (eli työpaikalla) on oma lääkehoitosuunnitelmansa."
  },
  {
    "category": "Lääkehoitoprosessi ja lääkehoitosuunnitelma",
    "question": "Tiedät, mihin lääkehoidon tehtäviin sairaanhoitaja tarvitsee kirjallisen luvan, kuka sen myöntää ja kuinka kauan lupa on voimassa.",
    "additionalInformation": "Esimerkki kirjallisesta luvasta: LOVe-lupa"
  },
  {
    "category": "Etiikka ja moniammatillisuus",
    "question": "Tiedät lääkehoidon toteuttamisen eettiset ohjeet. Toimit eettisten ohjeiden mukaan.",
    "additionalInformation": "Eettinen työskentely tarkoittaa mm. sitä, että kuuntelet potilaan toiveita, annat potilaan päättää, teet töitä vastuullisesti ja turvallisesti sekä hoidat jokaista potilasta yhtä hyvin. Eettinen työskentely ei voi olla itsekästä, vastuutonta ja epäasiallista."
  },
  {
    "category": "Etiikka ja moniammatillisuus",
    "question": "Tiedät, mitkä ovat eri ammattiryhmien vastuut, kun ammattilaiset toteuttavat lääkehoitoa eri toimintaympäristöissä. Tiedät myös lääkkeen käyttäjän vastuut.",
    "additionalInformation": "Tässä yhteydessä lääkkeen käyttäjä tarkoittaa esimerkiksi potilasta, joka käyttää lääkettä terveysvaivan hoitamiseen."
  },
  {
    "category": "Sairaanhoitajan tehtävät ja vastuu lääkehoitoprosessissa",
    "question": "Tiedät sairaanhoitajan vastuut ja velvollisuudet lääkehoitoprosessissa.",
    "additionalInformation": "Lääkehoitoprosessiin kuuluu monta vaihetta, kuten esimerkiksi lääkkeen määrääminen, lääkkeen antaminen ja lääkehoidon vaikutusten arviointi."
  },
  {
    "category": "Sairaanhoitajan tehtävät ja vastuu lääkehoitoprosessissa",
    "question": "Tunnistat tilanteet, joissa pitää informoida tai konsultoida muita potilaan lääkehoidon toteutukseen osallistuvia ammattihenkilöitä.",
    "additionalInformation": "Lääkehoidon ammattihenkilöllä on riittävä koulutus ja pätevyys lääkehoidon toteuttamiseen. Lääkehoidon ammattihenkilöitä ovat esimerkiksi lääkärit, sairaanhoitajat ja lähihoitajat."
  },
  {
    "category": "Sairaanhoitajan tehtävät ja vastuu lääkehoitoprosessissa",
    "question": "Kun toteutat lääkehoitoa, huomioit seuraavat asiat:\n\nturvallisuus\ntehokkuus\ntaloudellisuus \ntarkoituksenmukaisuus.",
    "additionalInformation": "Lääkehoidon turvallisuuteen vaikuttaa moni asia. Viranomaiset valvovat ja ohjaavat lääkehoidon turvallisuutta. Terveydenhuollon organisaation, toimintayksikön ja lääkehoitoa toteuttavan ammattihenkilön täytyy huolehtia, että potilaan lääkehoito on mahdollisimman riskitöntä ja hyvin suunniteltua. \n\nLääkehoidon tehokkuus tarkoittaa, että lääke auttaa potilasta saavuttamaan halutun terveysvaikutuksen, kuten oireiden lievittämisen tai sairauden parantamisen.  \n\nJotta lääkehoito on taloudellista, työntekijöiden täytyy huomioida lääkehoidon hinta ja kustannukset. \n\nLääkehoito on tarkoituksenmukaista, kun lääkkeitä käytetään oikein, tarpeen mukaan, ohjeiden mukaisesti, oikeaan aikaan ja sopivilla annoksilla. Tämä hyödyttää sekä potilasta että yhteiskuntaa"
  },
  {
    "category": "Lääkehoidon turvallisuus",
    "question": "Tunnistat lääkehoitoprosessin riskikohdat.",
    "additionalInformation": "Riskikohdat ovat lääkehoitoprosessin vaiheita, joiden aikana voi tapahtua haitallisia virheitä ja väärinymmärryksiä. Riskikohtia ovat esimerkiksi lääkehoidon suunnittelu ja määrääminen, lääkkeen annostelu, lääkehoidon seuranta ja potilasohjaus."
  },
  {
    "category": "Lääkehoidon turvallisuus",
    "question": "Tunnistat lääkehoidossa tapahtuvia vaaratilanteita ja haittatapahtumia.",
    "additionalInformation": "Lääkehoidon vaaratilanne tarkoittaa tilannetta, jossa lääkkeen käyttö aiheuttaa potilaalle haittaa tai vaaran. Tämä voi johtua esimerkiksi lääkkeen väärästä annostelusta, yhteisvaikutuksista muiden lääkkeiden kanssa tai potilaan yksilöllisestä reaktiosta lääkkeeseen. Vaaratilanne ei välttämättä johda haittatapahtumaan, mutta se voi aiheuttaa riskin potilaan turvallisuudelle. \n\nLääkehoidon haittatapahtumaa tarkoittaa tilannetta, jossa lääke aiheuttaa potilaalle haittaa eli ongelmia."
  },
  {
    "category": "Lääkehoidon turvallisuus",
    "question": "Osaat raportoida yksikön ohjeiden mukaisesti tapahtuneista vaaratilanteista ja haittatapahtumista.",
    "additionalInformation": "Lääkehoidon vaaratilanne tarkoittaa tilannetta, jossa lääkkeen käyttö aiheuttaa potilaalle haittaa tai vaaran. Tämä voi johtua esimerkiksi lääkkeen väärästä annostelusta, yhteisvaikutuksista muiden lääkkeiden kanssa tai potilaan yksilöllisestä reaktiosta lääkkeeseen. Vaaratilanne ei välttämättä johda haittatapahtumaan, mutta se voi aiheuttaa riskin potilaan turvallisuudelle. \n\nLääkehoidon haittatapahtuma tarkoittaa tilannetta, jossa lääke aiheuttaa potilaalle haittaa eli ongelmia."
  },
  {
    "category": "Lääkehoidon turvallisuus",
    "question": "Osaat tunnistaa lääkityspoikkeamat ja osaat raportoida niistä.",
    "additionalInformation": "Lääkityspoikkeama on virhe, joka tapahtuu lääkehoidon aikana. Lääkityspoikkeama voi alentaa lääkitysturvallisuutta ja johtaa haittatapahtumiin. Lääkityspoikkeamia ovat esimerkiksi väärän lääkkeen antaminen, väärä annostus ja puutteellinen lääkehoidon kirjaus."
  },
  {
    "category": "Lääkehoidon turvallisuus",
    "question": "Osaat toimia, kun tapahtuu haittatapahtuma.",
    "additionalInformation": "Lääkehoidon haittatapahtuma tarkoittaa tilannetta, jossa lääke aiheuttaa potilaalle haittaa eli ongelmia esimerkiksi allergisen reaktion."
  },
  {
    "category": "Lääkehoidon turvallisuus",
    "question": "Tiedät turvatuotteet ja osaat käyttää turvatuotteita.",
    "additionalInformation": "Turvatuote on menetelmä tai väline, jonka käytöllä tehdään lääkehoidosta turvallisempaa. Turvatuotteita ovat esimerkiksi turvaneulat ja annostelulaitteet."
  },
  {
    "category": "Lääkehoidon perustana olevat tiedot (farmakologia)",
    "question": "Tiedät farmakologian ja farmasian perusteet.",
    "additionalInformation": "Farmakologia on lääketieteen ala, joka tutkii, kuinka lääkeaineet vaikuttavat elimistöön eli esimerkiksi sisäelimiin, verenkiertoon ja hengitykseen. Lisäksi farmakologia tutkii, millainen vaikutus elimistöllä on lääkeaineisiin. \n\nFarmasia on lääketieteen ala, joka tutkii lääkkeiden kehittämistä, valmistamista, jakelua ja käyttöä."
  },
  {
    "category": "Lääkehoidon perustana olevat tiedot (farmakologia)",
    "question": "Ymmärrät, miten ihmisen anatomia ja fysiologia vaikuttavat lääkeaineiden antamiseen.",
    "additionalInformation": "Lääkeaine on aine, joka vaikuttaa elimistön toimintaan. Lääkeaineita käytetään sairauksien hoitoon tai ehkäisyyn. Esimerkiksi antibiootit ovat lääkeaineita, jotka tappavat bakteereja tai estävät niiden kasvua."
  },
  {
    "category": "Lääkehoidon perustana olevat tiedot (farmakologia)",
    "question": "Ymmärrät, miten ihmisen anatomia ja fysiologia vaikuttavat lääkeaineiden vaiheisiin ja vaikutuksiin elimistössä.",
    "additionalInformation": "Lääkeaine on aine, joka vaikuttaa elimistön toimintaan. Lääkeaineita käytetään sairauksien hoitoon tai ehkäisyyn. Esimerkiksi antibiootit ovat lääkeaineita, jotka tappavat bakteereja tai estävät niiden kasvua."
  },
  {
    "category": "Lääkehoidon perustana olevat tiedot (farmakologia)",
    "question": "Tiedät, mitä lääkeaineita käytetään yleisissä sairauksissa. Tiedät niiden vaikutukset ja yleisimmät sivuvaikutukset, haittavaikutukset ja yhteisvaikutukset.",
    "additionalInformation": "Sivuvaikutus on lääkehoidon seuraus, joka ei kuulu hoidon tavoitteisiin. Lääkehoidon yleisiä sivuvaikutuksia ovat päänsärky, pahoinvointi, vatsavaivat, lihaskivut ja ihottuma. Sivuvaikutus tarkoittaa usein samaa kuin haittavaikutus.\n\nHaittavaikutus on lääkehoidon negatiivinen seuraus. Lääkehoidon haittavaikutukset voivat olla lieviä (esim. päänsärky) mutta myös vakavia (esim. munuais- ja maksavauriot).\n\nLääkkeiden yhteisvaikutus tarkoittaa tilannetta, jossa yhden tai useamman lääkkeen samanaikainen käyttö vaikuttaa siihen, kuinka tehokasta ja turvallista lääkkeiden käyttö on. Yhteisvaikutukset voivat olla joko haitallisia tai hyödyllisiä. Haitalliset yhteisvaikutukset voivat esimerkiksi voimistaa lääkkeen haittavaikutuksia tai heikentää lääkkeen tehoa."
  },
  {
    "category": "Lääkehoidon perustana olevat tiedot (farmakologia)",
    "question": "Tunnistat riskilääkkeet ja otat huomioon niiden ominaisuudet lääkehoidon suunnittelussa.",
    "additionalInformation": "Riskilääkkeet ovat lääkkeitä, joiden määräämiseen ja käyttöön sisältyy suuri riski. Jos esimerkiksi riskilääkkeiden annostelussa tai säilytyksessä tapahtuu virhe, lääkkeen käyttäminen voi aiheuttaa vakavia haittavaikutuksia. Riskilääkkeitä ovat esimerkiksi veren hyytymiseen vaikuttavat lääkkeet, insuliinit, syöpälääkkeet ja opioidit. \n\nLääkkeen ominaisuudet kertovat, mitä lääkkeelle tapahtuu elimistössä ja miten se vaikuttaa elimistön toimintaan. \n\nLääkehoidon suunnittelun aikana ammattihenkilö tutustuu potilaan sairaushistoriaan ja suunnittelee sen perusteella, millainen lääkitys potilaalle määrätään. Lisäksi ammattihenkilö arvioi, kuinka lääkkeenanto tapahtuu ja millaisia riskejä lääkehoitoon voi sisältyä."
  },
  {
    "category": "Näyttöön perustuvan toiminta ja tietokantojen käyttö",
    "question": "Tiedät tärkeät luotettavan lääketiedon lähteet ja osaat hakea niistä tietoa:  \n\nLääketetokanta\nPharmaca Fennica\nLääkeopas/ terveyskirjasto\nLääkeinteraktiot ja -haitat\nLääke 75+\nHoitotyön Pharmaca \nLääketalo\nMyrkytystietokeskus\nHotus\nKäypähoito",
    "additionalInformation": "Lähde on aineisto tai materiaali, jonka avulla saat tietoa tietystä aiheesta."
  },
  {
    "category": "Näyttöön perustuvan toiminta ja tietokantojen käyttö",
    "question": "Ymmärrät lääkkeiden pakkausmerkinnät, pakkausselosteen ja valmisteyhteenvedon.",
    "additionalInformation": "Pakkausmerkintöjen avulla saat tietoa lääkkeen turvallisesta ja asianmukaisesta käytöstä. Tärkeitä pakkausmerkintöjä ovat esimerkiksi lääkkeen nimi, lääkemuoto, lääkkeen vahvuus, säilytysohjeet ja viimeinen käyttöpäivä. \n\nPakkausseloste sisältää tietoa lääkkeen käytöstä, annostelusta ja mahdollisista sivuvaikutuksista. Pakkausselosteessa kerrotaan muun muassa, mihin ja miten lääkettä käytetään, mitkä ovat lääkkeen mahdolliset haittavaikutukset ja kuinka lääke pitäisi säilyttää.\n. \nValmisteyhteenveto on viranomaisen hyväksymä asiakirja eli dokumentti, joka sisältää yksityiskohtaista tietoa lääkkeestä. Tämä asiakirja on tarkoitettu terveydenhuollon ammattilaisille. Se sisältää seuraavat osiot: lääkevalmisteen nimi, vaikuttavat aineet ja niiden määrät, lääkemuoto, kliiniset tiedot ja farmakologiset ominaisuudet sekä käyttö- ja käsittelyohjeet."
  },
  {
    "category": "Viestintä ja tiedonkulku turvallisessa lääkehoitoprosessissa",
    "question": "Osaat lääkehoitoon liittyvän suullisen ja kirjallisen viestinnän niin, että lääkehoito on turvallista potilaalle: \nOsaat kertoa lääkärille ja muille lääkehoitoa toteuttaville kaikki lääkehoitoon liittyvät asiat. \nOsaat suomeksi lääkemuodot, antotavat ja annosteluun liittyvän terminologian. \nOsaat toistaa lääkemääräyksen ja annetut ohjeet.\nOsaat varmistaa, kun olet epävarma.",
    "additionalInformation": "Lääkehoitoa toteuttavat henkilöt ovat yleensä ammattihenkilöitä, joilla on koulutus ja lupa osallistua lääkehoidon toteuttamiseen. Näitä ammattihenkilöitä ovat esimerkiksi lääkärit, sairaanhoitajat, terveydenhoitajat ja lähihoitajat."
  },
  {
    "category": "Viestintä ja tiedonkulku turvallisessa lääkehoitoprosessissa",
    "question": "Huomioit tietosuojan, kun puhut tai kirjoitat potilaan lääkehoidosta.",
    "additionalInformation": "Tietosuoja tarkoittaa, että potilaan tietoja ei saa kertoa ulkopuolisille"
  },
  {
    "category": "Asiakas-/potilaslähtöinen ohjaus",
    "question": "Osaat ohjata potilasta ja/tai potilaan läheisiä lääkkeiden ja eri lääkemuotojen oikeassa käytössä.\nOsaat ohjata potilasta niin, että hän ymmärtää miksi ja miten lääkettä otetaan. \nHuomioit erilaiset ja eri-ikäiset ihmiset.",
    "additionalInformation": "Lääkemuoto kertoo, millainen lääke on ja kuinka se annostellaan. Eri lääkemuotoja ovat esimerkiksi tabletit, kapselit ja injektiot."
  },
  {
    "category": "Asiakas-/potilaslähtöinen ohjaus",
    "question": "Osaat varmistaa, että potilas ymmärtää annetun ohjauksen ja osaa toteuttaa sitä.",
    "additionalInformation": ""
  },
  {
    "category": "Asiakas-/potilaslähtöinen ohjaus",
    "question": "Osaat kirjata lääkehoidon potilasohjauksen (suunniteltu ja annettu ohjaus).",
    "additionalInformation": ""
  },
  {
    "category": "Voimassa olevan lääkityksen ja riskitietojen tarkistaminen \nLääkehoidon tarpeiden arviointi",
    "question": "Osaat selvittää potilaan voimassa olevan lääkityksen ja sen ajantasaisuuden. (Lääkitykseen voi kuulua reseptilääkkeitä, itsehoitolääkkeeitä, luontaistuotteita ja kasvisrohtovalmisteita.)\nKäytät selvittämisessä eri lähteitä:\nKanta\nPotilastietojärjestelmä\nHaastattelu\nOmaiset",
    "additionalInformation": "Voimassa oleva lääkitys tarkoittaa potilaalle määrättyjä lääkkeitä, joita hän käyttää tällä hetkellä. \n\nReseptilääkkeitä ovat lääkärin määräämiä lääkkeitä, esimerkiksi antibiootit, verenpainelääkkeet ja keskushermostoon vaikuttavat lääkkeet. \n\nItsehoitolääke on lääke, jonka voi ostaa ilman reseptiä apteekista. Esimerkiksi monet särky- ja allergialääkkeet ovat itsehoitolääkkeitä. Itsehoitolääkkeestä tai valmisteesta käytetään myös sanaa käsikauppalääke.  \n\n\nLuontaistuote on luonnonmukainen valmiste, joka on valmistettu kasveista, yrteistä, mineraaleista tai eläinperäisistä aineista. Luontaistuotteita ovat esimerkiksi yrttivalmisteet, vitamiinit, kivennäisaineet ja erilaiset ravintolisät. \n \n \nKasvisrohtovalmisteet ovat valmisteita, joiden vaikuttavat aineet ovat peräisin kasveista."
  },
  {
    "category": "Voimassa olevan lääkityksen ja riskitietojen tarkistaminen \nLääkehoidon tarpeiden arviointi",
    "question": "Osaat selvittää potilaan lääkehoitoa koskevat allergiatiedot ja riskitiedot.",
    "additionalInformation": "Kun lääkehoidon ammattihenkilö tietää potilaan allergia- ja riskitiedot, hän ei vahingossa anna potilaalle lääkettä, joka voi aiheuttaa potilaalle haittaa."
  },
  {
    "category": "Lääkemääräykset ja reseptit",
    "question": "Tiedät, mitä tietoja lääkemääräyksessä ja reseptissä pitää olla. Osaat kysyä, jos määräys on epäselvä.",
    "additionalInformation": "Resepti on dokumentti, jonka avulla potilas voi hakea reseptilääkkeen apteekista. Resepti kirjataan sähköisesti Kanta-palveluun, josta apteekin työntekijät voivat tarkistaa reseptin voimassaolon."
  },
  {
    "category": "Lääkemääräykset ja reseptit",
    "question": "Ymmärrät lääkemääräyksien ja reseptien merkinnät.",
    "additionalInformation": ""
  },
  {
    "category": "Lääkemääräykset ja reseptit",
    "question": "Tiedät, miksi potilaalle on määrätty lääkkeitä ja mikä on lääkityksen tavoite.",
    "additionalInformation": ""
  },
  {
    "category": "Lääkehoidon toteuttamisen suunnittelu ja kirjaaminen",
    "question": "Kun suunnittelet potilaan lääkehoidon toteuttamista, otat huomioon hänen kokonaislääkityksensä sekä yksilölliset tekijät.",
    "additionalInformation": "Yksilölliset tekijät ovat ominaisuuksia, jotka voivat erottaa potilaan muista potilaista. Näitä ominaisuuksia voivat olla esimerkiksi potilaan ikä, paino, sukupuoli, kulttuuritausta, perhetilanne, mielentila ja toimintakyky.\n\nKokonaislääkitys tarkoittaa kaikkia lääkkeitä, joita potilas käyttää."
  },
  {
    "category": "Lääkehoidon toteuttamisen suunnittelu ja kirjaaminen",
    "question": "Osaat selvittää lääkkeen annostelussa huomioitavat asiat (esim. normaaliannokset ja maksimiannokset, ajankohta, lääkkeiden puolittamismahdollisuus).",
    "additionalInformation": "Normaaliannos on annosmäärä, joka sopii potilaalle ja saa aikaan halutun vaikutuksen ilman haittavaikutuksia.\n\nMaksimiannos on annosmäärä, jonka ylittäminen voi olla haitallista tai vaarallista.\n\nAnnostelun ajankohta on lääkekohtainen tieto siitä, milloin tai missä tilanteissa lääke pitää ottaa. Potilas voi esimerkiksi käyttää lääkettä, joka täytyy aina ottaa ennen ruokailua.\n\nKun lääke (tabletti) puolitetaan, se jaetaan kahteen osaan."
  },
  {
    "category": "Lääkehoidon toteuttamisen suunnittelu ja kirjaaminen",
    "question": "Osaat tarkastaa ja huomioida potilaan lääkkeiden keskeisimmät haitta- ja yhteisvaikutukset sekä yhteisvaikutukset alkoholin kanssa:\nRiskBase\nHerbBAse\nINXBase",
    "additionalInformation": "Haittavaikutus on lääkehoidon negatiivinen seuraus. Lääkehoidon haittavaikutukset voivat olla lieviä (esim. päänsärky) mutta myös vakavia (esim. munuais- ja maksavauriot).\n\nLääkkeiden yhteisvaikutus tarkoittaa tilannetta, jossa yhden tai useamman lääkkeen samanaikainen käyttö vaikuttaa siihen, kuinka tehokasta ja turvallista lääkkeiden käyttö on. Yhteisvaikutukset voivat olla joko haitallisia tai hyödyllisiä. Haitalliset yhteisvaikutukset voivat esimerkiksi voimistaa lääkkeen haittavaikutuksia tai heikentää lääkkeen tehoa."
  },
  {
    "category": "Lääkehoidon toteuttamisen suunnittelu ja kirjaaminen",
    "question": "Osaat kirjata lääkkeiden antoon liittyvät asiat lääkehoitosuunnitelman ohjeen mukaan.",
    "additionalInformation": "Lääkehoitosuunnitelma on dokumentti, joka ohjaa lääkehoidon toteuttamista. Toimintayksiköllä (eli työpaikalla) on oma lääkehoitosuunnitelmansa."
  },
  {
    "category": "Lääkehoidon toteuttamisen suunnittelu ja kirjaaminen",
    "question": "Osaat tehdä ajantasaisen lääkityslistan.",
    "additionalInformation": "Lääkityslista on lista, jolla näkyy kaikki potilaan käyttämät lääkkeet (esim. reseptilääkkeet, itsehoitolääkkeet ja luontaistuotteet)."
  },
  {
    "category": "Lääkehoidon toteuttamisen suunnittelu ja kirjaaminen",
    "question": "Osaat tunnistaa, arvioida ja kirjata lääkehoidon vaikutuksia ja mahdollisia haitta- ja yhteisvaikutuksia.",
    "additionalInformation": "Haittavaikutus on lääkehoidon negatiivinen seuraus. Lääkehoidon haittavaikutukset voivat olla lieviä (esim. päänsärky) mutta myös vakavia (esim. munuais- ja maksavauriot).\n\nLääkkeiden yhteisvaikutus tarkoittaa tilannetta, jossa yhden tai useamman lääkkeen samanaikainen käyttö vaikuttaa siihen, kuinka tehokasta ja turvallista lääkkeiden käyttö on. Yhteisvaikutukset voivat olla joko haitallisia tai hyödyllisiä. Haitalliset yhteisvaikutukset voivat esimerkiksi voimistaa lääkkeen haittavaikutuksia tai heikentää lääkkeen tehoa."
  },
  {
    "category": "Lääkkeiden hankkiminen ja säilytys",
    "question": "Tiedät, mitä tarkoitetaan lääkevalikoimalla.",
    "additionalInformation": "Lääkevalikoima tarkoittaa niitä lääkkeitä, joita potilas voi saada apteekista, sairaalasta tai terveydenhuollon laitoksesta. Eri paikoissa voi olla erilainen lääkevalikoima."
  },
  {
    "category": "Lääkkeiden hankkiminen ja säilytys",
    "question": "Tiedät, miten lääkkeiden annosjakelu toimii",
    "additionalInformation": "Annosjakelu on palvelu, jossa apteekki tai sairaala-apteekki annostelee lääkkeet valmiiksi ja toimittaa ne potilaalle."
  },
  {
    "category": "Lääkkeiden hankkiminen ja säilytys",
    "question": "Ymmärrät lääkkeiden hankintaan liittyvät taloudelliset näkökulmat (lääkkeen hinta, geneerinen substituutio ja viitehintajärjestelmä, sairausvakuutus).",
    "additionalInformation": "Kun lääkäri määrää potilaalle lääkkeen, apteekki voi tarjota potilaalle edullisemman lääkevaihtoehdon, jos siinä on sama määrä vaikuttavaa ainetta ja muut vaihtamisen kriteerit täyttyvät. Tätä toimintaa kutsutaan geneeriseksi substituutioksi.  \n\nLääkkeen viitehinta on korkein hinta, jonka perusteella sairausvakuutuskorvaus voidaan laskea lääkkeille, jotka kuuluvat viitehintajärjestelmään.\n\nSairausvakuutus korvaa kuluja (rahallisia menoja), joita sairaus, raskaus tai synnytys aiheuttaa. Suomessa sairausvakuutus on osa sosiaaliturvaa."
  },
  {
    "category": "Lääkkeiden hankkiminen ja säilytys",
    "question": "Tiedät lääkkeiden oikeat säilytyspaikat (lääkekaappi, lääkehuone ja jääkaappi). Noudatat vaatimuksia ja ohjeita.",
    "additionalInformation": "Kun tavaraa tai tuotetta ei käytetä, sen voi laittaa säilytyspaikkaan eli esimerkiksi kaappiin tai varastoon."
  },
  {
    "category": "Lääkkeiden hankkiminen ja säilytys",
    "question": "Tiedät, millaisissa olosuhteissa (mm. lämpö, kosteus, valo, turvallisuus) lääkkeet pitää säilyttää.",
    "additionalInformation": ""
  },
  {
    "category": "Lääkkeiden hankkiminen ja säilytys",
    "question": "Osaat säilyttää potilaalle valmiiksi jaetut lääkkeet oikein, jotta sekaantumisriskiä ei ole.",
    "additionalInformation": "Lääkkeiden sekaantumisriski tarkoittaa mahdollisuutta, että potilas saa väärän lääkkeen tai väärän annoksen lääkettä."
  },
  {
    "category": "Huumausaineet",
    "question": "Osaat tilata, käsitellä ja säilyttää huumausaineiksi luokitellut lääkkeet. Osaat kirjata niiden käytön.",
    "additionalInformation": "Huumausaineet ovat aineita, joilla on voimakas vaikutus keskushermostoon ja jotka voivat johtaa riippuvuuteen ja aineen väärinkäyttöön."
  },
  {
    "category": "Lääkkeiden aseptinen käsittely ja käyttökuntoon saattaminen",
    "question": "Kun käsittelet lääkkeitä, työskentelet aseptisesti, huolellisesti sekä työ- ja potilasturvallisesti. Otat työskentelyssäsi huomioon lääkemuodon ja antotavan sekä lääkkeen muut vaatimukset (esimerkiksi suodatinneulan käyttö lasiampullan kanssa).",
    "additionalInformation": ""
  },
  {
    "category": "Lääkkeiden aseptinen käsittely ja käyttökuntoon saattaminen",
    "question": "Osaat varmistaa, että lääkkeet ovat käyttökelpoisia.",
    "additionalInformation": "Kun asia on käyttökelpoinen, sitä voi käyttää. Jos asia ei ole käyttökelpoinen, sen käyttö voi olla vaikeaa, hyödytöntä, riskialtista tai vaarallista."
  },
  {
    "category": "Lääkkeiden aseptinen käsittely ja käyttökuntoon saattaminen",
    "question": "Noudatan ohjeita, jotka koskevat lääkkeellisten kaasujen ja muiden erityisosaamista vaativien lääkkeiden säilytystä, käsittelyä ja hävittämistä.",
    "additionalInformation": "Lääkkeellisiä kaasuja käytetään esimerkiksi anestesiassa, kivunlievityksessä ja hengityksen tukemisessa. Lääkkeellisiin kaasuihin kuuluvat esimerkiksi lääkehappi O2 ja ilokaasu N2O."
  },
  {
    "category": "Lääkkeiden hävittäminen",
    "question": "Osaat ohjata potilasta hävittämään tarpeettomat ja käyttökelvottomat lääkkeet siten, että ne eivät aiheuta vaaraa terveydelle tai ympäristölle.",
    "additionalInformation": "Lääke hävitetään eli poistetaan, kun se on vanhentunut, tarpeeton tai käyttökelvoton.\n\nKun potilas ei (enää) tarvitse lääkettä, lääke on tarpeeton.  \n\nKun potilas ei voi käyttää lääkettä, lääke on käyttökelvoton."
  },
  {
    "category": "Lääkkeiden hävittäminen",
    "question": "Osaat lajitella lääkejätteen sen ominaisuuksien ja toimintayksikön ohjeiden mukaisesti.",
    "additionalInformation": "Lääkejätteeseen voi kuulua esimerkiksi vanhentuneita lääkkeitä, tarpeettomia lääkkeitä ja lääkepakkauksia (ruiskuja, neuloja jne.)."
  },
  {
    "category": "Lääkelaskenta",
    "question": "Osaat lääkelaskennan, kun annat lääkettä. Otat huomioon eri muotoiset lääkkeet, erilaiset antotavat ja myös potilaan iän sekä sen, millainen sairaus hänellä on.\nYksikkömuunnokset \nAnnoslaskut \nLääkkeen riittävyys\nInfuusiolaskut\nLaimennuslaskut\nKaasulaskut",
    "additionalInformation": "Lääkelaskujen yksikkömuunnokset tarkoittavat sitä, että lääkelaskussa oleva mittayksikkö (esim. millilitra) muutetaan toiseksi mittayksiköksi.\n\nAnnoslaskun avulla selvitetään, mikä on oikea lääkkeen annos potilaalle. \n\nKun lasketaan lääkkeen riittävyys, tavoitteena on selvittää, kuinka kauan lääkemäärä riittää potilaan hoitoon.\n\nInfuusiolaskun avulla selvitetään, millainen tiputusnopeus tai annos infuusiossa pitäisi olla. \n\nLaimennuslaskun avulla selvitetään, kuinka paljon alkuperäistä liuosta ja laimennusnestettä (esim. keittosuolaliuosta) tarvitaan, jotta saadaan haluttu liuoksen pitoisuus. \n\nKaasulaskun avulla voidaan esim. selvittää, kuinka paljon ja millä virtausnopeudella kaasua annetaan potilaalle."
  },
  {
    "category": "Lääkkeiden jakaminen",
    "question": "Osaat jakaa lääkkeet ilman virheitä lääkityslistan mukaisesti lääketarjottimelle tai dosettiin.",
    "additionalInformation": "Lääketarjotin on lääkehoidon työväline, jonka avulla lääkkeet pidetään järjestyksessä ja kuljetetaan potilaalle. \n\nDosetti on yleensä muovinen rasia, jossa on lokeroita (pieniä laatikkoja) lääkkeitä varten. Dosetin avulla lääkkeet voi annostella etukäteen esimerkiksi päivien ja kellonaikojen perusteella."
  },
  {
    "category": "Lääkkeiden jakaminen",
    "question": "Käytät kaksoistarkastamista, jotta olet varma, että lääkkeet, annokset ja lääkelista on oikein.",
    "additionalInformation": "Kaksoistarkastaminen tarkoittaa prosessia, jonka aikana kaksi terveydenhuollon ammattilaista tarkistaa, että lääkkeet on annosteltu ja jaettu oikein"
  },
  {
    "category": "Lääkkeiden jakaminen",
    "question": "Osaat merkitä potilaalle jaetut lääkeannokset siten, että oikea potilas saa oikean lääkkeen oikeaan aikaan.",
    "additionalInformation": ""
  },
  {
    "category": "Lääkehoitoon liittyvät äkillistä hoitoa vaativat tilanteet",
    "question": "Tiedät, mitä ovat elvytys- ja muut ensiapulääkkeet",
    "additionalInformation": "Ensiapulääke on lääke, jolla pyritään vakauttamaan potilaan tila hätätilanteen aikana. Ensiapulääkettä voidaan tarvita esimerkiksi silloin, kun potilas on saanut epilepsiakohtauksen, allergisen reaktion tai sydänpysähdyksen.  \n\nElvytyslääke on lääke, jota käytetään elvytystilanteessa eli sydänpysähdyksen hoidossa."
  },
  {
    "category": "Lääkehoitoon liittyvät äkillistä hoitoa vaativat tilanteet",
    "question": "Tiedät, miten lääkkeisiin liittyvää allergista reaktiota hoidetaan.",
    "additionalInformation": ""
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Osaat varmistaa potilaan henkilöllisyyden (oikea potilas).",
    "additionalInformation": ""
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Osaat varmistaa lääkkeen oikeellisuuden (oikea lääke ja oikea annos, oikea lääkemuoto).",
    "additionalInformation": ""
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Osaat varmistaa oikean lääkkeen otto-/ antoajankohdan (oikea aika).",
    "additionalInformation": ""
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Otat huomioon lääkemuodon ja antoreitin vaatimukset (oikea antotapa).",
    "additionalInformation": "Lääkkeen antoreitti tarkoittaa tapaa, jolla lääke annetaan potilaalle. Se kuvaa, mihin kehon osaan tai järjestelmään lääke toimitetaan. Lääke voidaan esimerkiksi annostella ruoansulatuskanavaan suun tai peräsuolen kautta."
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Osaat ohjata potilasta lääkkeen oikeassa ottotavassa. Osaat varmistaa, että potilas osaa ja kykenee ottamaan lääkkeen (oikea ohjaus).",
    "additionalInformation": "Lääkkeen ottotapa kertoo, miten lääke otetaan tai annetaan potilaalle."
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Seuraat lääkkeen vaikutuksia (oikea seuranta).",
    "additionalInformation": ""
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Varmistat tiedonkulun ja osaat kirjata tiedot lääkkeen antamisesta (oikea kirjaaminen).",
    "additionalInformation": "Lääkehoidon aikana tieto kulkee eli liikkuu henkilöiden ja järjestelmien välillä. Tiedonkulkua helpottavat esimerkiksi kattavat ja oikea-aikaiset kirjaukset, sähköisten järjestelmien käyttö ja suullinen raportointi."
  },
  {
    "category": "”Lääkehoidon oikeat” ja lääkkeen antaminen",
    "question": "Tiedät, miten toimia tilanteessa, jossa potilas ei halua lääkettä. Huomioit potilaan oikeuden kieltäytyä lääkehoidosta.",
    "additionalInformation": "Oikeus kieltäytyä tarkoittaa, että potilas voi sanoa lääkehoidolle ”ei”."
  },
  {
    "category": "Enteraaliset reitit",
    "question": "Osaat antaa lääkkeitä suun kautta huomioiden eri lääkemuotojen vaatimukset (esim. entero- ja depottabletit, resoribletit ja oraalineste).",
    "additionalInformation": ""
  },
  {
    "category": "Enteraaliset reitit",
    "question": "Osaat antaa lääkkeitä nenämahaletkun tai PEG:n (perkutaaninen endoskooppinen gastrostomia) kautta",
    "additionalInformation": ""
  },
  {
    "category": "Enteraaliset reitit",
    "question": "Osaat antaa lääkkeitä peräsuolen kautta (peräruiskeet, suppositorio, voide).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, luonnollista tietä annettavat lääkkeet",
    "question": "Osaat antaa lääkkeen hengitysteihin (inhalaationeste, -jauhe tai -sumute).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, luonnollista tietä annettavat lääkkeet",
    "question": "Osaat antaa lääkkeitä ihon kautta (laastarit ja voiteet).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, luonnollista tietä annettavat lääkkeet",
    "question": "Osaat antaa lääkkeitä silmään (silmätipat, -voiteet, geelit ja -vedet).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, luonnollista tietä annettavat lääkkeet",
    "question": "Osaat antaa lääkkeitä nenään (tippa, sumute ja voide).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, luonnollista tietä annettavat lääkkeet",
    "question": "Osaat antaa lääkkeitä korvaan (tippa ja voide).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, luonnollista tietä annettavat lääkkeet",
    "question": "Osaat antaa lääkkeitä emättimeen (tabletti, voide, vagitorio ja rengas).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, injektiot",
    "question": "Osaat antaa lääkkeen injektiona ihon alle.",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, injektiot",
    "question": "Osaat antaa lääkkeen injektiona lihakseen.",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset reitit, injektiot",
    "question": "Osata antaa lääkkeen injektiona ihon sisään.",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Tiedät, kuka saa annostella ja antaa lääkkeitä i.v.",
    "additionalInformation": "i.v. -lääkkeiden annosteluun pitää olla tietty koulutus ja siihen pitää suorittaa lääkelupa."
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Osaat arvioida ja suunnitella potilaan nestetasapainoa ja nestehoidon tarvetta ja seurantaa.",
    "additionalInformation": "Kun nestetapapainossa ei ole ongelmia, kehossa on riittävästi nestettä eli nestettä ei ole liikaa tai liian vähän."
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Osaat tarvittavan välineistön sekä sen oikean ja aseptisen käytön (esim. ruiskut, nesteensiirtolaitteet ja kolmitiehanat).",
    "additionalInformation": "Nesteensiirtolaitteiston avulla neste siirretään potilaan kehoon. Nesteensiirtolaitteistoon kuuluu esimerkiksi infuusioletku eli “tippaletku”."
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Osaat nesteensiirtolaitteiston käyttökuntoon saattamisen.",
    "additionalInformation": "Nesteensiirtolaitteiston avulla neste siirretään potilaan kehoon. Nesteensiirtolaitteistoon kuuluu esimerkiksi infuusioletku eli “tippaletku”. \n\nKun nesteensiirtolaite saatetaan käyttökuntoon, varmistetaan, että infuusioletku on täytetty nesteellä ja se on valmiina käyttöön."
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Hallitset suonensisäisesti annettavan lääkkeen valmistelun, laimentamisen ja lisäämisen infuusionesteeseen. Tiedät, miten täytetään lääkelisäyslappu.",
    "additionalInformation": "Lääkeliuos laimennetaan, kun tavoitteena on pienentää lääkeliuoksen pitoisuutta. Tällöin lääkeliuokseen lisätään esimerkiksi vettä tai suolaliuosta. \n\nKun infuusionesteeseen lisätään lääkettä, otetaan käyttöön lääkelisäyslappu. Lääkelisäyslappuun kirjoitetaan tiedot lisättävästä lääkkeestä, kuten lääkkeen nimi ja vaikuttavan aineen määrä sekä lääkkeen lisääjän nimi."
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Osaat laskea ja asettaa infuusion antonopeuden (ml/h ja gtt/min).",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Osaat käyttää infuusio- ja ruiskupumppuja.",
    "additionalInformation": ""
  },
  {
    "category": "Parenteraaliset, laskimonsisäiset lääkkeet",
    "question": "Osaat käyttää kipupumppua ja kipukasettia.",
    "additionalInformation": ""
  },
  {
    "category": "Perifeerisen laskimon kanylointi",
    "question": "Osaat kanyloida perifeerisen laskimon. Osaat ottaa huomioon komplikaatioriskit ja käsittelet kanyyliä oikein.",
    "additionalInformation": ""
  },
  {
    "category": "Lääkkeellinen happi",
    "question": "Osaat käyttää hapen antamiseen tarvittavaa välineistöä turvallisesti (kaasupullo, virtausmittari eli rotametri, happiviikset ja happinaamarit).",
    "additionalInformation": ""
  },
  {
    "category": "Lääkkeellinen happi",
    "question": "Osaat laskea hapen riittävyyden.",
    "additionalInformation": "Kun lasketaan lääkkeen riittävyys, tavoitteena on selvittää, kuinka kauan käytössä oleva lääkemäärä riittää potilaan hoitoon."
  },
  {
    "category": "Lääkkeellinen happi",
    "question": "Osaat huomioida potilaan erityistarpeet (esim. COPD), kun toteutat happihoitoa.",
    "additionalInformation": ""
  },
  {
    "category": "Verensiirto",
    "question": "Olet suorittanut ABO-verkkokurssin.",
    "additionalInformation": "ABO-verkkokurssi on terveysalan ammattilaisille tarkoitettu verkkokurssi."
  },
  {
    "category": "Verensiirto",
    "question": "Osaat huomioida verivalmisteiden antamiseen liittyvät vastuut ja erityisvaatimukset.",
    "additionalInformation": "Verivalmisteita ovat punasoluvalmisteet, verihiutalevalmisteet ja plasmavalmisteet."
  },
  {
    "category": "Verensiirto",
    "question": "Osaat säilyttää verivalmisteita ohjeiden mukaisesti.",
    "additionalInformation": "Verivalmisteita ovat punasoluvalmisteet, verihiutalevalmisteet ja plasmavalmisteet."
  },
  {
    "category": "Verensiirto",
    "question": "Tiedät toimenpiteet ennen verensiirtoja ja osaat tehdä ne.",
    "additionalInformation": ""
  },
  {
    "category": "Verensiirto",
    "question": "Osaat tarkistustoimenpiteet verensiirtohoitoon liittyen (potilaan identifiointi ja valmisteen käyttökelpoisuuden varmistaminen).",
    "additionalInformation": "Verensiirtohoidon aikana verivalmistetta (eli esimerkiksi punasoluja, verihiutaleita tai plasmaa) siirretään potilaan kehoon."
  },
  {
    "category": "Verensiirto",
    "question": "Osaat aloittaa ohjattuna verensiirtohoidon ja tehdä biologisen esikokeen.",
    "additionalInformation": "Biologinen esikoe tarkoittaa testiä, joka tehdään ennen verensiirtoa tai lääkkeen antoa."
  },
  {
    "category": "Verensiirto",
    "question": "Tiedät verensiirtohoidon komplikaatiot.",
    "additionalInformation": "Verensiirtohoidon aikana verivalmistetta (eli esimerkiksi punasoluja, verihiutaleita tai plasmaa) siirretään potilaan kehoon."
  },
  {
    "category": "Verensiirto",
    "question": "Osaat tarkkailla ja arvioida potilasta verensiirtohoidon aikana ja sen jälkeen.",
    "additionalInformation": "Verensiirtohoidon aikana verivalmistetta (eli esimerkiksi punasoluja, verihiutaleita tai plasmaa) siirretään potilaan kehoon."
  },
  {
    "category": "Verensiirto",
    "question": "Osaat dokumentoida verensiirtohoidon.",
    "additionalInformation": "Verensiirtohoidon aikana verivalmistetta (eli esimerkiksi punasoluja, verihiutaleita tai plasmaa) siirretään potilaan kehoon."
  },
  {
    "category": "Rokottaminen",
    "question": "Tiedät, mitä sairauksia rokotteilla ehkäistään.",
    "additionalInformation": ""
  },
  {
    "category": "Rokottaminen",
    "question": "Tiedät kansallisen rokotusohjelman rokotteet.",
    "additionalInformation": "Kansallisen rokotusohjelman tavoitteena on, että suomalaiset saavat suojan taudeilta, jotka voidaan estää rokotusten avulla."
  },
  {
    "category": "Rokottaminen",
    "question": "Tiedät rokotustekniikat.",
    "additionalInformation": ""
  },
  {
    "category": "Rokottaminen",
    "question": "Tunnistat rokottamisen vasta-aiheet.",
    "additionalInformation": "Vasta-aihe tarkoittaa tilanteita tai tekijöitä, jotka voivat tehdä rokotteen antamisesta haitallista tai vaarallista"
  },
  {
    "category": "Rokottaminen",
    "question": "Osaat kertoa rokotuksen mahdollisista haittavaikutuksista.",
    "additionalInformation": "Haittavaikutus on lääkehoidon negatiivinen seuraus. Lääkehoidon haittavaikutukset voivat olla lieviä (esim. päänsärky) mutta myös vakavia (esim. anafylaktinen reaktio)."
  }
]

export default questions
