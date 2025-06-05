const Introduction = () => {
  return (
    <>
      <div className="flex-col-container">
        <h1>LÄÄKITSE-LÄÄKEHOIDON KOMPETENSSIN ITSEARVIOINTI SELKOKIELELLÄ</h1>
        <p>
          Tämä on työkalu lääkehoidon kompetenssin osaamisen itsearviointiin. Siinä on kuvattu konkreettisesti, millaista osaamista sairaanhoitajalta lääkehoidossa vaaditaan.
        </p>
        <p>
          LÄÄKITSE-työkalu sisältää lääkehoidon eri osa-alueet. LÄÄKITSE-työkalun avulla voit arvioida osaamistasi sairaanhoitajan vastuualueella ja lääkehoidon tehtävissä. Se auttaa sinua arvioimaan myös suomen kielen ja etenkin lääkehoitosanaston osaamistasi. Lisäksi opit sen avulla asettamaan lääkehoidon osaamistavoitteita kliiniseen harjoitteluun.
        </p>
      </div>
      <div className="flex-col-container instructions">
        <h2>OHJEET</h2>
        <p>Tee itsearviointi lääkehoidon opintojakson lopuksi/ennen harjoittelua. Vastaa väittämiin rehellisesti.</p>
        <p><strong>Jos vastaat johonkin kohtaan "En osaa":</strong></p>
        <p>Opiskele tätä asiaa lisää ja/tai tee tästä kohdasta tavoite sinun kliiniseen harjoitteluusi. <br></br>
          "Tavoite kliiniseen harjoitteluun: Osaan käyttää infuusiopumppua. Osaan käyttää ruiskupumppua."</p>
        <p><strong>Jos vastaat johonkin kohtaan "En ymmärrä":</strong></p>
        <p>Tarkista ensin vaikeiden sanojen selkokieliset selitykset tukisanastosta. Arvioi sen jälkeen uudelleen, osaatko asian.
          Jos tukisanaston avun jälkeen et ymmärrä tai et osaa asiaa, sinun täytyy opiskella lisää lääkehoitoa ja/tai suomen kieltä</p>
      </div>
    </>
  )
}

export default Introduction
