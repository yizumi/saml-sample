Rails.application.routes.draw do
  resources :saml, only: %i[index] do
    collection do
      post :consume
    end
  end
end
