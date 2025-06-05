import { useState } from "react"
import QuestionnaireTable from "./QuestionnaireTable"
import Summary from "./Summary"
import Introduction from "./Introduction"

import questions from "./Questions"
import logo_tamk from './assets/logo_tamk.svg'
import logo_sasu from './assets/logo_sasu.png'
import logo_jotpa from './assets/logo_jotpa.png'
import './styles.css'

const App = () => {
  const [answers, setAnswers] = useState({})

  const handleAnswer = (id, text, value) => {
    setAnswers({
      ...answers,
      [id]: {
        "text": text,
        "value": value,
      }
    })
  }

  return (
    <>
      <header>
        <nav>
          <img src={logo_tamk} alt="TAMK logo" />
        </nav>
      </header>
      <main className="flex-col-container center">
        <Introduction />
        <QuestionnaireTable
          questions={questions}
          answers={answers}
          onAnswer={handleAnswer}
        />
        <Summary
          questions={questions}
          answers={answers}
        />
      </main>
      <footer>
        <img src={logo_sasu} alt="Sairaanhoitajaksi Suomessa -logo" />
        <img src={logo_jotpa} alt="JOTPA logo" />
      </footer>
    </>
  )
}

export default App
