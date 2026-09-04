import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { SessionGate } from './components/SessionGate'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SessionGate><App /></SessionGate>
  </StrictMode>,
)
