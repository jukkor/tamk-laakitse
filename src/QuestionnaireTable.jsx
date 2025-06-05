import './styles.css'

const QuestionnaireTable = ({ questions, answers, onAnswer }) => {
  // Group questions by category
  const questionsByCategory = questions.reduce((acc, question, i) => {
    if (!acc[question.category]) acc[question.category] = []
    acc[question.category].push({ ...question, index: i })
    return acc
  }, {})

  return (
    <div className='tableContainer'>
      <table>
        <thead>
          <tr>
            <th>Osaamisalue</th>
            <th>Kriteeri</th>
            <th>Vastaus</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(questionsByCategory).map(([category, items]) =>
            items.map((q, i) => (
              <tr key={q.index}>
                {i === 0 && (
                  <td rowSpan={items.length}>
                    <strong>{category}</strong>
                  </td>
                )}
                <td>
                  {q.question}
                </td>
                <td >
                  <div className='answersCell'>
                    <div className='answersCell__answerOptions'>
                      {["Osaan", "En osaa", "En ymmärrä"].map((option) => (
                        <label key={option}>
                          <input
                            type="radio"
                            name={`q-${q.index}`}
                            value={option}
                            checked={answers[q.index]?.value === option}
                            onChange={() => onAnswer(q.index, q.question, option)}
                          />
                          <span>{option}</span>
                        </label>
                      ))}
                    </div>
                    {q.additionalInformation && q.additionalInformation.trim() !== "" && (
                      <span title={q.additionalInformation}>
                        ❓
                      </span>
                    )}
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

export default QuestionnaireTable
