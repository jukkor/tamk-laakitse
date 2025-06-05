import { useRef } from 'react'
import './styles.css'

const Summary = ({ questions, answers }) => {
  const answeredDontKnowDontUnderstand = Object.entries(answers)
    .filter(([, obj]) => obj.value !== "Osaan")
    .map(([index, obj]) => ({
      index: parseInt(index),
      val: obj.value,
      text: questions[index]?.question || ""
    }))

  const scores = {}
  Object.entries(answers).forEach(([index, obj]) => {
    const i = parseInt(index)
    const q = questions[i]
    if (!q) return
    const cat = q.category
    if (!scores[cat]) scores[cat] = { known: 0, total: 0 }
    scores[cat].total += 1
    if (obj.value === "Osaan") scores[cat].known += 1
  })

  const totalKnown = Object.values(scores).reduce((sum, v) => sum + v.known, 0)
  const totalQuestions = Object.values(scores).reduce((sum, v) => sum + v.total, 0)

  const summaryRef = useRef()

  const handleExportPDF = () => {
    import('html2pdf.js').then(({ default: html2pdf }) => {
      html2pdf(summaryRef.current, {
        margin: 10,
        filename: 'OmaNimi_LAAKITSE_yhteenveto.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2 },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
      })
    })
  }

  return (
    <div className="text-container padding-top-bottom">
      <div ref={summaryRef}>
        <h2>YHTEENVETO</h2>
        <h3>Yhteensä {(totalKnown / totalQuestions * 100 || 0).toFixed(1).replace('.', ',')} % osattu</h3>

        <div className='avoidBreak'>
          <h3>Prosentit kategorioittain</h3>
          <ul>
            {Object.entries(scores).map(([category, { known, total }]) => (
              <li key={category}>
                <strong>{category}</strong>: {(known / total * 100).toFixed(0)} %
              </li>
            ))}
          </ul>
        </div>

        {answeredDontKnowDontUnderstand.length > 0 && (
          <div className='pageBreakBefore' >
            <h3>Vastattu "En osaa" tai "En ymmärrä"</h3>
            {Object.entries(
              answeredDontKnowDontUnderstand.reduce((acc, { index, text, val }) => {
                if (!acc[val]) acc[val] = []
                acc[val].push({ index, text })
                return acc
              }, {})
            ).map(([answer, items]) => (
              <div
                key={answer}
                className='avoidBreak'
              >
                <h4>{answer}</h4>
                <ul>
                  {items.map(({ index, text }) => (
                    <li key={index}>{text}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}

      </div>
      <button onClick={handleExportPDF}>Vie yhteenveto PDF-tiedostoon</button>
    </div>
  )
}

export default Summary
